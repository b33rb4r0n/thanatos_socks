---
title: SOCKS
description: Enable a SOCKS5 proxy on the Mythic server tunneled through this agent
---

# SOCKS

The `socks` command enables a SOCKS5 proxy on the Mythic server that tunnels traffic through the Thanatos agent. This allows you to route network traffic through the compromised host, useful for pivoting and accessing internal networks.

## Syntax

```bash
socks -port <number> -action {start|stop} [-username u] [-password p]
```

## Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-port` | Yes | Port number for the SOCKS proxy (use 0 for auto-assignment) |
| `-action` | Yes | Action to perform: `start` or `stop` |
| `-username` | No | Username for SOCKS authentication (optional) |
| `-password` | No | Password for SOCKS authentication (optional) |

## Usage Examples

### Start SOCKS Proxy (Auto-assign Port)
```bash
socks -port 0 -action start
```

### Start SOCKS Proxy on Specific Port
```bash
socks -port 1080 -action start
```

### Start SOCKS Proxy with Authentication
```bash
socks -port 1080 -action start -username myuser -password mypass
```

### Stop SOCKS Proxy
```bash
socks -port 1080 -action stop
```

## Features

- **SOCKS5 Protocol**: Full SOCKS5 implementation with authentication support
- **Auto Port Assignment**: Use port 0 to let Mythic assign an available port
- **Authentication**: Optional username/password authentication
- **Traffic Tunneling**: All traffic is tunneled through the agent
- **Compatible Tools**: Works with proxychains, proxychains4, and other SOCKS5 clients

## Technical Details

The SOCKS implementation:
- Uses the SOCKS5 protocol for maximum compatibility
- Handles both authenticated and non-authenticated connections
- Maintains persistent connections for efficient data transfer
- Supports both TCP and UDP traffic (TCP only in current implementation)
- Integrates seamlessly with Mythic's SOCKS infrastructure

## Security Considerations

- SOCKS proxies can be detected by network monitoring tools
- Authentication helps prevent unauthorized use
- Monitor for unusual network traffic patterns
- Consider the legal and ethical implications of traffic tunneling

## Troubleshooting

**Connection Issues:**
- Ensure the agent has network connectivity
- Check if the specified port is available
- Verify firewall settings allow the SOCKS traffic

**Authentication Problems:**
- Ensure username/password are correctly specified
- Check for special characters that might need escaping

**Performance Issues:**
- SOCKS adds overhead to network traffic
- Consider the bandwidth limitations of the compromised host
- Monitor agent performance during heavy SOCKS usage

## Related Commands

- `redirect` - Set up TCP redirectors for specific port forwarding
- `ssh` - Use SSH for secure tunneling and pivoting
- `netstat` - Check network connections and ports

---

*Contributed by B4r0n*
