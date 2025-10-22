---
title: Screenshot
description: Take a screenshot of the desktop (Windows only)
---

# Screenshot

The `screenshot` command captures a screenshot of the desktop and uploads it to Mythic. This is useful for visual reconnaissance and monitoring user activity.

## Syntax

```bash
screenshot
```

## Parameters

This command takes no parameters.

## Usage Examples

### Basic Screenshot
```bash
screenshot
```

## Features

- **Desktop Capture**: Captures the entire desktop screen
- **BMP Format**: Saves screenshots in BMP format for maximum compatibility
- **Automatic Upload**: Screenshots are automatically uploaded to Mythic
- **Windows Only**: Currently only supported on Windows systems
- **PowerShell Integration**: Uses PowerShell and .NET for reliable screen capture

## Technical Details

The screenshot implementation:
- Uses PowerShell with .NET `System.Drawing` and `System.Windows.Forms`
- Captures the primary screen using `Screen.PrimaryScreen.Bounds`
- Creates a bitmap and copies screen contents using `Graphics.CopyFromScreen`
- Saves the screenshot as a BMP file in the system temp directory
- Encodes the image as base64 for transmission to Mythic
- Automatically cleans up temporary files

## Output

The command returns:
- Success message with file size information
- The screenshot is uploaded to Mythic as a downloadable file
- File appears in the Mythic file browser with a unique filename

## Security Considerations

- Screenshots may contain sensitive information
- Consider the privacy implications of capturing user screens
- Screenshots can be large files, affecting bandwidth
- May trigger antivirus alerts due to screen capture behavior

## Troubleshooting

**Permission Issues:**
- Ensure the agent has sufficient privileges to access the desktop
- Some security software may block screen capture operations

**File Size Issues:**
- Large screenshots may take time to upload
- Consider screen resolution impact on file size

**PowerShell Issues:**
- Ensure PowerShell execution policy allows script execution
- Check if .NET Framework is properly installed

## Limitations

- **Windows Only**: Currently only works on Windows systems
- **Primary Screen**: Only captures the primary monitor
- **BMP Format**: Uses BMP format which can result in large file sizes
- **No Compression**: Screenshots are not compressed to reduce file size

## Related Commands

- `clipboard` - Access clipboard contents
- `askcreds` - Prompt for user credentials
- `ps` - List running processes

---

*Contributed by B4r0n*
