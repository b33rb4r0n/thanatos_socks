---
title: AskCreds
description: Prompt the user for Windows credentials using CredUI (Windows only)
---

# AskCreds

The `askcreds` command prompts the user for their Windows credentials using the Windows Credential UI (CredUI). This creates a legitimate-looking credential prompt that users are likely to trust and enter their credentials into.

## Syntax

```bash
askcreds [reason]
```

## Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `reason` | No | Custom reason to display to the user (default: "Restore Network Connection") |

## Usage Examples

### Basic Credential Prompt
```bash
askcreds
```

### Custom Reason
```bash
askcreds "Please verify your credentials to continue"
```

### Network-Related Reason
```bash
askcreds "Windows needs to verify your identity for network access"
```

## Features

- **Legitimate UI**: Uses Windows CredUI for authentic-looking prompts
- **Custom Messages**: Allows custom reasons for credential requests
- **Timeout Protection**: 60-second timeout with automatic cleanup
- **Window Management**: Closes interfering credential windows
- **Memory Safety**: Properly cleans up sensitive data from memory
- **Thread Safety**: Uses separate thread for UI interaction

## Technical Details

The askcreds implementation:
- Uses Windows CredUI API (`CredUIPromptForWindowsCredentialsW`)
- Creates a separate thread for the credential prompt
- Implements 60-second timeout with automatic cleanup
- Handles window enumeration to close interfering dialogs
- Supports both domain and local account credentials
- Properly cleans up sensitive data from memory

## Output

The command returns:
- **Success**: Username, domain (if applicable), and password
- **Timeout**: "Credential prompt timed out" after 60 seconds
- **Cancel**: "The operation was canceled by the user"
- **Error**: Specific error messages for various failure scenarios

## Security Considerations

⚠️ **High Risk Command**: This command directly harvests user credentials
- Use only in authorized penetration testing scenarios
- Consider legal and ethical implications
- May trigger security alerts or user suspicion
- Credentials are transmitted back to Mythic (ensure secure communication)

## Attack Mapping

- **MITRE ATT&CK**: T1056.001 - Input Capture: Keylogging
- **Category**: Credential Access
- **Sub-technique**: Input Capture

## Troubleshooting

**UI Not Appearing:**
- Ensure the agent is running in an interactive session
- Check if the user is logged in and active
- Verify Windows CredUI is functioning properly

**Timeout Issues:**
- Users may need more time to enter credentials
- Consider the user's familiarity with credential prompts
- Some users may be suspicious of unexpected prompts

**Permission Issues:**
- Ensure the agent has sufficient privileges
- Some security software may block credential UI access

## Limitations

- **Windows Only**: Currently only works on Windows systems
- **Interactive Session**: Requires an interactive user session
- **User Dependent**: Success depends on user cooperation
- **Timeout**: Limited to 60-second timeout window

## Use Cases

- **Credential Harvesting**: Collect user credentials for lateral movement
- **Social Engineering**: Leverage user trust in Windows credential prompts
- **Persistence**: Gather credentials for maintaining access
- **Privilege Escalation**: Obtain higher-privilege credentials

## Related Commands

- `clipboard` - Access clipboard contents for potential credentials
- `screenshot` - Capture desktop for visual reconnaissance
- `getprivs` - Check current privileges

---

*Contributed by B4r0n*
