---
title: Clipboard
description: Retrieve the contents of the clipboard (Windows only)
---

# Clipboard

The `clipboard` command retrieves the current contents of the Windows clipboard. This is useful for gathering sensitive information that users may have copied, such as passwords, tokens, or other data.

## Syntax

```bash
clipboard
```

## Parameters

This command takes no parameters.

## Usage Examples

### Basic Clipboard Access
```bash
clipboard
```

## Features

- **Text Retrieval**: Accesses text data from the Windows clipboard
- **Unicode Support**: Handles Unicode text properly
- **Empty Detection**: Detects when clipboard is empty or contains no text
- **Windows Only**: Currently only supported on Windows systems
- **Low-Level API**: Uses Windows API for reliable clipboard access

## Technical Details

The clipboard implementation:
- Uses Windows API functions (`OpenClipboard`, `GetClipboardData`, etc.)
- Supports Unicode text format (`CF_UNICODETEXT`)
- Implements retry logic for clipboard access (up to 10 attempts)
- Handles wide character strings properly
- Cleans up memory and handles errors gracefully

## Output

The command returns:
- **Text Content**: The actual clipboard text if available
- **Empty Message**: "Clipboard is empty or contains no text" if no text data
- **Error Messages**: Specific error messages if clipboard access fails

## Security Considerations

- Clipboard contents may contain sensitive information
- Consider the privacy implications of accessing user clipboard data
- Clipboard access may be logged by security software
- Some applications may clear clipboard contents for security

## Troubleshooting

**Access Denied:**
- Ensure the agent has sufficient privileges
- Some applications may lock the clipboard
- Try running the command again if clipboard is busy

**Empty Clipboard:**
- The clipboard may genuinely be empty
- Some applications may not store text in the expected format
- Clipboard may contain non-text data (images, files, etc.)

**Unicode Issues:**
- The implementation handles Unicode properly
- Special characters should be displayed correctly

## Limitations

- **Windows Only**: Currently only works on Windows systems
- **Text Only**: Only retrieves text data, not images or files
- **No History**: Cannot access clipboard history, only current contents
- **Single Access**: Each command execution gets the current clipboard state

## Use Cases

- **Password Harvesting**: Capture passwords users have copied
- **Token Collection**: Gather authentication tokens from clipboard
- **Data Exfiltration**: Collect sensitive data users have copied
- **Reconnaissance**: Understand what data users are working with

## Related Commands

- `screenshot` - Capture desktop screenshots
- `askcreds` - Prompt for user credentials
- `getenv` - Get environment variables

---

*Contributed by B4r0n*
