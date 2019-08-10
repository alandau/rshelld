#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#ifndef PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
#define PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE 0x00020016
#endif

typedef void *HPCON;

typedef HRESULT (WINAPI *CreatePseudoConsoleProc)(
    _In_ COORD size,
    _In_ HANDLE hInput,
    _In_ HANDLE hOutput,
    _In_ DWORD dwFlags,
    _Out_ HPCON* phPC
);

typedef void (WINAPI *ClosePseudoConsoleProc)(
    _In_ HPCON hPC
);

CreatePseudoConsoleProc CreatePseudoConsole;
ClosePseudoConsoleProc ClosePseudoConsole;

typedef struct ProcessListNode {
    HANDLE process;
    HANDLE waitthead;
    struct ProcessListNode *next;
} ProcessListNode;

typedef struct ProcessList {
    CRITICAL_SECTION lock;
    ProcessListNode *list;
} ProcessList;

typedef struct Console {
    HPCON hConsole;
    HANDLE in;
    HANDLE out;
    HANDLE process;
} Console;

typedef struct ThreadParam {
    HANDLE pipe;
    SOCKET sock;
    HANDLE process;
} ThreadParam;

typedef struct WaitThreadParam {
    HANDLE process;
    HPCON console;
    HANDLE stdinthread, stdoutthread;
    SOCKET sock;
} WaitThreadParam;

ProcessList process_list;

void ProcessListInit(ProcessList *list) {
    InitializeCriticalSection(&list->lock);
    list->list = NULL;
}

void ProcessListAdd(ProcessList *list, HANDLE process, HANDLE waitthread) {
    ProcessListNode *node = malloc(sizeof(ProcessListNode));
    EnterCriticalSection(&list->lock);
    node->process = process;
    node->waitthead = waitthread;
    node->next = list->list;
    list->list = node;
    LeaveCriticalSection(&list->lock);
}

void ProcessListRemove(ProcessList *list, HANDLE process, HANDLE *waitthread) {
    if (waitthread) {
        *waitthread = NULL;
    }
    EnterCriticalSection(&list->lock);
    if (list->list == NULL) {
        // Empty, do nothing
        assert(0);
    } else if (list->list->process == process) {
        // First, move head pointer
        ProcessListNode *cur = list->list;
        list->list = list->list->next;
        if (waitthread) {
            *waitthread = cur->waitthead;
        }
        free(cur);
    } else {
        ProcessListNode *prev = list->list;
        for (ProcessListNode *cur = prev->next; cur; prev = cur, cur = cur->next) {
            if (cur->process == process) {
                prev->next = cur->next;
                if (waitthread) {
                    *waitthread = cur->waitthead;
                }
                free(cur);
            }
        }
    }
    LeaveCriticalSection(&list->lock);
}

BOOL WINAPI CtrlHandler(DWORD fdwCtrlType) {
    EnterCriticalSection(&process_list.lock);
    while (process_list.list != NULL) {
        HANDLE process = process_list.list->process;
        HANDLE waitthread;
        // We need to duplicate the waitthread handle, since it will be
        // closed by WaitThread during our WaitForSingleObject, which
        // is undefined
        DuplicateHandle(GetCurrentProcess(), process_list.list->waitthead, GetCurrentProcess(), &waitthread,
            0, FALSE, DUPLICATE_SAME_ACCESS);
        LeaveCriticalSection(&process_list.lock);

        TerminateProcess(process, 0);
        WaitForSingleObject(waitthread, INFINITE);
        CloseHandle(waitthread);

        EnterCriticalSection(&process_list.lock);
    }
    LeaveCriticalSection(&process_list.lock);

    // FALSE means unhandled, so next (default) handler will terminate process
    return FALSE;
}

BOOL CreateConsole(Console *console, HANDLE *inputRead, HANDLE *outputWrite) {
    HANDLE inRead = NULL, inWrite = NULL;
    HANDLE outRead = NULL, outWrite = NULL;
    
    if (!CreatePipe(&inRead, &inWrite, NULL, 0)) {
        goto err;
    }

    if (!CreatePipe(&outRead, &outWrite, NULL, 0)) {
        goto err;
    }

    HPCON hPC;
    COORD size = { 80, 24 };
    HRESULT hr = CreatePseudoConsole(size, inRead, outWrite, 0, &hPC);
    if (FAILED(hr)) {
        SetLastError(hr);
        goto err;
    }

    console->hConsole = hPC;
    console->in = inWrite;
    console->out = outRead;
    console->process = NULL;
    *inputRead = inRead;
    *outputWrite = outWrite;
    return TRUE;
err:
    if (inRead) CloseHandle(inRead);
    if (inWrite) CloseHandle(inWrite);
    if (outRead) CloseHandle(outRead);
    if (outWrite) CloseHandle(outWrite);
    return FALSE;
}

BOOL PrepareStartupInformation(HPCON hConsole, STARTUPINFOEX *psi)
{
    STARTUPINFOEX si;
    memset(&si, 0, sizeof(si));
    si.StartupInfo.cb = sizeof(STARTUPINFOEX);

    // Discover the size required for the list
    size_t bytesRequired;
    InitializeProcThreadAttributeList(NULL, 1, 0, &bytesRequired);

    // Allocate memory to represent the list
    si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, bytesRequired);
    if (!si.lpAttributeList) {
        return FALSE;
    }

    // Initialize the list memory location
    if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &bytesRequired)) {
        HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
        return FALSE;
    }

    // Set the pseudoconsole information into the list
    if (!UpdateProcThreadAttribute(si.lpAttributeList,
        0,
        PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
        hConsole,
        sizeof(hConsole),
        NULL,
        NULL)) {
        HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
        return FALSE;
    }

    *psi = si;

    return TRUE;
}

HANDLE LaunchProcess(const wchar_t *cmdline, HPCON hConsole, HANDLE in, HANDLE out, STARTUPINFOEX *si) {
    wchar_t *cmdLineMutable = _wcsdup(cmdline);

    if (!cmdLineMutable) {
        return NULL;
    }

    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof(pi));

    // Call CreateProcess
    if (!CreateProcess(NULL, cmdLineMutable, NULL, NULL, FALSE,
            EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &si->StartupInfo, &pi)) {
        free(cmdLineMutable);
        return NULL;
    }
    CloseHandle(pi.hThread);
    free(cmdLineMutable);
    CloseHandle(in);
    CloseHandle(out);
    return pi.hProcess;
}

SOCKET CreateListeningSocket(const char *addrstr, int port) {
    WSADATA wsaData;
    int res = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (res != 0) {
        printf("WSAStartup failed with error: %d\n", res);
        return INVALID_SOCKET;
    }

    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) {
        printf("socket() failed: %d\n", WSAGetLastError());
        WSACleanup();
        return INVALID_SOCKET;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(addrstr);
    addr.sin_port = ntohs(port);
    res = bind(s, (struct sockaddr *)&addr, sizeof(addr));
    if (res != 0) {
        printf("bind() failed: %d\n", WSAGetLastError());
        closesocket(s);
        WSACleanup();
        return INVALID_SOCKET;
    }

    res = listen(s, 10);
    if (res != 0) {
        printf("listen() failed: %d\n", WSAGetLastError());
        closesocket(s);
        WSACleanup();
        return INVALID_SOCKET;
    }

    return s;
}

DWORD WINAPI StdinThread(LPVOID param) {
    ThreadParam *args = (ThreadParam *)param;

    char buf[4096];
    while (1) {
        int count = recv(args->sock, buf, sizeof(buf), 0);
        if (count <= 0) {
            int error;
            if (count < 0 && (error = WSAGetLastError()) != WSAECONNABORTED) {
                printf("Error reading stdin from socket: %d\n", error);
            }
            break;
        }
        DWORD written;
        BOOL b = WriteFile(args->pipe, buf, count, &written, NULL);
        if (!b) {
            printf("Error writing stdin to pipe: %u\n", GetLastError());
            break;
        }
    }
    CloseHandle(args->pipe);
    TerminateProcess(args->process, 0);
    free(args);
    return 0;
}

DWORD WINAPI StdoutThread(LPVOID param) {
    ThreadParam *args = (ThreadParam *)param;

    char buf[4096];
    DWORD count;
    while (1) {
        BOOL b = ReadFile(args->pipe, buf, sizeof(buf), &count, NULL);
        if (!b) {
            DWORD error = GetLastError();
            if (error != ERROR_BROKEN_PIPE) {
                printf("Error reading stdout from pipe: %u\n", error);
            }
            break;
        }
        if (count == 0) {
            // EOF
            break;
        }
        int res = send(args->sock, buf, count, 0);
        if (res < 0) {
            printf("Error writing stdout to socket: %d\n", WSAGetLastError());
            break;
        }
    }
    CloseHandle(args->pipe);
    TerminateProcess(args->process, 0);
    free(args);
    return 0;
}

DWORD WINAPI WaitThread(LPVOID param) {
    WaitThreadParam *args = (WaitThreadParam *)param;
    WaitForSingleObject(args->process, INFINITE);

    HANDLE myself;
    ProcessListRemove(&process_list, args->process, &myself);
    CloseHandle(myself);

    struct sockaddr_in addr;
    int addrlen = sizeof(addr);
    getpeername(args->sock, (struct sockaddr *)&addr, &addrlen);

    ClosePseudoConsole(args->console);
    closesocket(args->sock);

    // ClosePseudoHandle signals StdoutThread, closesocket signals StdinThread
    WaitForSingleObject(args->stdinthread, INFINITE);
    CloseHandle(args->stdinthread);
    WaitForSingleObject(args->stdoutthread, INFINITE);
    CloseHandle(args->stdoutthread);

    // Close process handle last since the stdin or stdout threads might use
    // it to terminate process to signal us
    CloseHandle(args->process);

    printf("Closed connection from %s:%d\n", inet_ntoa(addr.sin_addr), htons(addr.sin_port));
    free(args);
    return 0;
}

int wmain(int argc, wchar_t *argv[]) {
    HMODULE hLib = LoadLibrary(L"kernel32.dll");
    FARPROC proc = GetProcAddress(hLib, "CreatePseudoConsole");
    if (!proc) {
        printf("Can't find CreatePseudoConsole in kernel32.dll, need Windows 10 1809 or later\n");
        return 1;
    }

    CreatePseudoConsole = (CreatePseudoConsoleProc)proc;
    ClosePseudoConsole = (ClosePseudoConsoleProc)GetProcAddress(hLib, "ClosePseudoConsole");

    SOCKET accept_socket = CreateListeningSocket("127.0.0.1", 8023);
    if (accept_socket == INVALID_SOCKET) {
        return 1;
    }

    ProcessListInit(&process_list);
    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    printf("Listening on %s:%d, press Ctrl+C to stop\n", "127.0.0.1", 8023);

    while (1) {
        Console console;
        console.hConsole = NULL;
        HANDLE process = NULL, stdinthread = NULL, stdoutthread = NULL, waitthread = NULL;
        ThreadParam *stdinparam = NULL, *stdoutparam = NULL;
        WaitThreadParam *waitparam = NULL;
        SOCKET s = INVALID_SOCKET;

        struct sockaddr_in addr;
        int addrlen = sizeof(addr);
        s = accept(accept_socket, (struct sockaddr *)&addr, &addrlen);
        if (s == INVALID_SOCKET) {
            printf("accept() failed: %d\n", WSAGetLastError());
            continue;
        }

        printf("Connection from %s:%d\n", inet_ntoa(addr.sin_addr), htons(addr.sin_port));

        HANDLE in, out;
        if (!CreateConsole(&console, &in, &out)) {
            printf("Can't create console: %u\n", GetLastError());
            goto err;
        }

        STARTUPINFOEX si;
        if (!PrepareStartupInformation(console.hConsole, &si)) {
            printf("Can't prepare startup info: %u\n", GetLastError());
            goto err;
        }

        process = LaunchProcess(L"cmd.exe", console.hConsole, in, out, &si);
        if (!process) {
            printf("Can't launch process: %u\n", GetLastError());
            goto err;
        }

        stdinparam = (ThreadParam *)malloc(sizeof(ThreadParam));
        stdinparam->sock = s;
        stdinparam->pipe = console.in;
        stdinparam->process = process;
        stdinthread = CreateThread(NULL, 0, StdinThread, stdinparam, 0, NULL);
        if (stdinthread == NULL) {
            printf("Can't create stdin thread: %u\n", GetLastError());
            goto err;
        }

        stdoutparam = (ThreadParam *)malloc(sizeof(ThreadParam));
        stdoutparam->sock = s;
        stdoutparam->pipe = console.out;
        stdoutparam->process = process;
        stdoutthread = CreateThread(NULL, 0, StdoutThread, stdoutparam, 0, NULL);
        if (stdoutthread == NULL) {
            printf("Can't create stdout thread: %u\n", GetLastError());
            goto err;
        }

        waitparam = (WaitThreadParam *)malloc(sizeof(WaitThreadParam));
        waitparam->console = console.hConsole;
        waitparam->process = process;
        waitparam->sock = s;
        waitparam->stdinthread = stdinthread;
        waitparam->stdoutthread = stdoutthread;
        waitthread = CreateThread(NULL, 0, WaitThread, waitparam, 0, NULL);
        if (waitthread == NULL) {
            printf("Can't create wait thread: %u\n", GetLastError());
            goto err;
        }

        ProcessListAdd(&process_list, process, waitthread);
        continue;

    err:
        if (console.hConsole) {
            ClosePseudoConsole(console.hConsole);
        }
        if (process) {
            TerminateProcess(process, 0);
            CloseHandle(process);
        }
        if (stdinthread) {
            TerminateThread(stdinthread, 0);
            CloseHandle(stdinthread);
        }
        if (stdoutthread) {
            TerminateThread(stdoutthread, 0);
            CloseHandle(stdoutthread);
        }
        if (waitthread) {
            TerminateThread(waitthread, 0);
            CloseHandle(waitthread);
        }
        free(stdinparam);
        free(stdoutparam);
        free(waitparam);
        if (s != INVALID_SOCKET) {
            closesocket(s);
        }
    }

    return 0;
}
