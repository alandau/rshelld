# rshelld - Remote shell with terminal emulation for Windows

`rshelld` listens on a port and on connection runs a command with its input/output redirected to the socket. The distinguishing feature, compared to e.g. `netcat`, is support for terminal emulation. When running an interactive shell, such as `cmd.exe` or `powershell.exe`, this means colors and special keys (e.g., Arrow Up for command history) are working.

Note that `rshelld` is not related to `rsh` (the precursor to `ssh`) in any way, except in the general sense of both being remote shells, so an `rsh` client will NOT be able to talk to an `rshelld` server.

## Download

Download `rshelld.exe` from the [Releases](https://github.com/alandau/rshelld/releases) page.

## Usage

```
Usage: rshelld [OPTION]...
Listen for TCP connections and run shell with input/output connected to socket.

Options:
  -c cmdline    Program with arguments to run upon connection.
                Use "quotes" if command line contains spaces. Default: cmd.exe
  -g            Listen on all interfaces (0.0.0.0).
                Default: Listen only on localhost (127.0.0.1).
  -p port       Listen on the specified port. Default: 8023
  -s WxH        Terminal size in characters. Default: 80x24
  -h, --help    Display this help and exit

Examples:
  rshelld               Listen on port 8023 on localhost only, run cmd.exe
  rshelld -p 1234 -g    Listen on port 1234 on all interfaces, run cmd.exe
  rshelld -c powershell Run powershell.exe instead of cmd.exe
```

On the client side, make sure local echo and line editing are turned off.
- For PuTTY, in the main Session pane choose Raw for Connection Type, and in the Terminal pane choose Force Off for both Local Echo and Local Line Editing.
- For Linux console, including WSL, use `stty raw -echo; nc localhost 8023; stty sane` or `telnet localhost 8023`.

## Security

All data is passed in plaintext (no encryption), so it is advisable to only use `rshelld` on `localhost`. This is the default, which can be overridden with the `-g` option. The envisioned use case is to use another tool, such as SSH, that does encryption and port forwarding, and forward the `rshelld` listening port over that secure connection.

## System Requirements

Windows 10 1809 (32- or 64-bit) or later is required. `rshelld` uses the Windows Pseudoconsole API that first appeared in this version.

## For Software Developers

`rshelld` uses the `CreatePseudoConsole` function from the Windows Pseudoconsole API to create a pseudo-terminal (PTY) in which the shell executes. This API does the heavy lifting to convert the shell's console I/O into terminal escape sequences. `rshelld` sends and receives these escape sequences over a TCP socket.

## License

MIT
