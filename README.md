<p align="center">
  <img alt="Thanatos Logo" src="agent_icons/thanatos.svg" height="50%" width="50%">
</p>

# Thanatos

[![GitHub License](https://img.shields.io/github/license/MythicAgents/thanatos)](https://github.com/MythicAgents/thanatos/blob/main/LICENSE)
[![GitHub Release](https://img.shields.io/github/v/release/MythicAgents/thanatos)](https://github.com/MythicAgents/thanatos/releases/latest)
[![Release](https://github.com/MythicAgents/thanatos/workflows/Release/badge.svg)](https://github.com/MythicAgents/thanatos/actions/workflows/release.yml)

Thanatos is a Windows and Linux C2 agent written in rust.

## Contributors
- **Original Author**: Matt Ehrnschwender (@M_alphaaa)
- **Contributor**: B4r0n - Added SOCKS proxy functionality, screenshot capture, clipboard access, and credential prompting capabilities

# Installation
To install Thanatos, you will need [Mythic](https://github.com/its-a-feature/Mythic) set up on a machine.

In the Mythic root directory, use `mythic-cli` to install the agent.
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/thanatos
sudo ./mythic-cli payload start thanatos
```

Thanatos supports the http C2 profile:  
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
sudo ./mythic-cli c2 start http
```

## Features
  - Background job management
  - Built-in ssh client
    * Connect to a machine and download/upload files between that machine and Mythic
    * Get directory listings from machines using sftp
    * Spawn agents on machines using ssh
    * ssh-agent hijacking
  - Streaming portscan
  - Stand up TCP redirectors
  - **SOCKS5 Proxy** - Tunnel traffic through the agent (contributed by B4r0n)
  - **Screenshot Capture** - Take desktop screenshots on Windows (contributed by B4r0n)
  - **Clipboard Access** - Retrieve clipboard contents on Windows (contributed by B4r0n)
  - **Credential Prompting** - Prompt users for Windows credentials using CredUI (contributed by B4r0n)


## Future Additions
  - v0.2.0
    * [x] Socks proxying ✅ (Implemented by B4r0n)
    * [ ] Windows token manipulation
    * [ ] More browser script integration
    * [ ] DNS C2 profile
    * [ ] p2p capabilities
    * [ ] In memory shellcode execution `execute-shellcode`

## General Commands

Command | Syntax | Description
------- | ------ | -----------
askcreds | `askcreds [reason]` | Prompt the user for Windows credentials using CredUI (Windows only).
cat | `cat [file]` | Output the contents of a file.
cd | `cd [new directory]` | Change directory.
clipboard | `clipboard` | Retrieve the contents of the clipboard (Windows only).
cp | `cp [source] [destination]` | Copy a file from [source] to [destination].
download | `download [path]` | Download a file from the target system (supports relative paths).
exit | `exit` | Exit the agent.
getenv | `getenv` | Get the current environment variables.
getprivs | `getprivs` | Get the privileges of the agent session.
jobkill | `jobkill [job id]` | Shutdown a running background job.
jobs | `jobs` | List currently running background jobs.
ls | `ls [directory]` | List files or directories (supports relative paths).
mkdir | `mkdir [directory]` | Make a new directory.
mv | `mv [source] [destination]` | Move a file from [source] to [destination] (supports relative paths).
portscan | `portscan [popup]` | Scan a list of IPs for open ports.
ps | `ps` | Get a list of currently running processes.
pwd | `pwd` | Print working directory.
redirect | `redirect [<bindhost>:<bindport>:<connecthost>:<connectport>]` | Setup a TCP redirector on the remote system.
rm | `rm [path]` | Remove a file or directory (supports relative paths).
screenshot | `screenshot` | Take a screenshot of the desktop (Windows only).
setenv | `setenv [name] [value]` | Set environment variable [name] to [value].
shell | `shell [command]` | Run a shell command with `bash -c` on Linux or `cmd.exe /c` on Windows in a new thread.
sleep | `sleep [interval][units] [jitter]` | Set the sleep interval and jitter (supports unit suffixing).
socks | `socks -port <number> -action {start|stop} [-username u] [-password p]` | Enable a SOCKS5 proxy on the Mythic server tunneled through this agent.
ssh | `ssh [popup]` | Use ssh to execute commands, download/upload files or grab directory listings.
ssh-agent | `ssh-agent [-c <socket>] [-d] [-l]` | Connect to running ssh agent sockets on the host or list identities.
ssh-spawn | `ssh-spawn [popup]` | Spawn a Mythic agent on a remote host using ssh.
unsetenv | `unsetenv [var]` | Unset an environment variable.
upload | `upload [popup]` | Upload a file to the host machine.

### Windows-specific Commands
Command | Syntax | Description
------- | ------ | -----------
powershell | `powershell [command]` | Run a command using `powershell.exe /c` in a new thread.
