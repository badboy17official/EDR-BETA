use tokio::sync::mpsc;
use log::{info, error, debug};
use std::collections::HashSet;
use std::path::Path;

mod config;
mod monitor;
mod ebpf_monitor; // newly added
mod scanner;
mod api_client;
mod policy_engine;
mod offline_queue;

// Set global log level
fn init_logger() {
    std::env::set_var("RUST_LOG", "info");
    env_logger::init();
}

#[tokio::main]
async fn main() {
    init_logger();
    info!("Starting Hybrid EDR Endpoint Agent");

    // Load config
    let cfg = config::load_config("config.json");
    let quarantine_target = cfg.quarantine_dir.clone();
    
    // Initialize channel for IPC between inotify thread and tokio worker async loop
    let (tx, mut rx) = mpsc::channel(100);
    
    // Mount eBPF Kernel Sensor asynchronously alongside our user-space file hashing loop
    let _ebpf = match ebpf_monitor::EbpfMonitor::new() {
        Ok(m) => {
            info!("Kernel eBPF Sensor successfully loaded inside EDR agent.");
            Some(m)
        }
        Err(e) => {
            log::warn!("Kernel sensors disabled: {}. Falling back to standard inotify...", e);
            None
        }
    };
    
    // Local Memory caching + duplication checking
    let mut cache = scanner::LocalCache::new(cfg.cache_capacity);
    let mut processing_queue = HashSet::new();
    
    // HTTP API Client
    let api = api_client::AgentApiClient::new(cfg.clone());

    // Spawn watcher thread - notify is inherently synchronous
    let _watcher = match monitor::start_monitoring(&cfg.monitor_dir, tx) {
        Ok(w) => w,
        Err(e) => {
            error!("Failed to start native file monitor: {}", e);
            std::process::exit(1);
        }
    };

    info!("Agent running, listening for file creation on {}...", cfg.monitor_dir);

    // Async main worker loop consuming file events
    while let Some(path) = rx.recv().await {
        if let Err(e) = flush_offline_queue(&api, &cfg.offline_queue_path, &mut cache, &quarantine_target).await {
            debug!("Offline queue flush skipped: {}", e);
        }

        let path_str = path.to_string_lossy().to_string();
        
        // Prevent event spamming same file
        if processing_queue.contains(&path_str) {
            continue;
        }
        processing_queue.insert(path_str.clone());

        // 1. Hash the file
        let sha256 = match scanner::compute_sha256(&path) {
            Ok(hash) => hash,
            Err(e) => {
                debug!("Could not read/hash file (likely swept up early): {:?}", e);
                processing_queue.remove(&path_str);
                continue;
            }
        };

        info!("New file detected: {:?} | SHA256: {}", path, sha256);

        if let Some(verdict) = cache.get(&sha256) {
            info!(
                "local_cache_hit sha256={} classification={} risk_score={}",
                sha256,
                verdict.classification,
                verdict.risk_score
            );
            apply_policy(&path, &quarantine_target, &verdict.classification);
            processing_queue.remove(&path_str);
            continue;
        }

        match api.lookup_hash(&sha256).await {
            Ok(Some(verdict)) => {
                info!(
                    "backend_hash_hit sha256={} classification={} risk_score={}",
                    sha256,
                    verdict.classification,
                    verdict.risk_score
                );
                cache.insert(sha256.clone(), verdict.clone());
                apply_policy(&path, &quarantine_target, &verdict.classification);
            }
            Ok(None) => {
                info!("backend_hash_miss sha256={}", sha256);
                match api.upload_file(&path).await {
                    Ok(task_id) => {
                        info!("file_uploaded task_id={} sha256={}", task_id, sha256);
                        if let Some(verdict) = api.poll_task_status(&task_id).await {
                            info!(
                                "verdict_received task_id={} classification={} risk_score={}",
                                task_id,
                                verdict.classification,
                                verdict.risk_score
                            );
                            cache.insert(sha256.clone(), verdict.clone());
                            apply_policy(&path, &quarantine_target, &verdict.classification);
                        } else {
                            error!("verdict_timeout_or_failed task_id={} sha256={}", task_id, sha256);
                            let _ = offline_queue::enqueue(
                                &cfg.offline_queue_path,
                                &offline_queue::QueuedEvent {
                                    path: path_str.clone(),
                                    sha256: sha256.clone(),
                                },
                            );
                        }
                    }
                    Err(api_error) => {
                        error!("api_upload_failed sha256={} error={}", sha256, api_error);
                        let _ = offline_queue::enqueue(
                            &cfg.offline_queue_path,
                            &offline_queue::QueuedEvent {
                                path: path_str.clone(),
                                sha256: sha256.clone(),
                            },
                        );
                    }
                }
            }
            Err(e) => {
                error!("api_lookup_failed sha256={} error={}", sha256, e);
                let _ = offline_queue::enqueue(
                    &cfg.offline_queue_path,
                    &offline_queue::QueuedEvent {
                        path: path_str.clone(),
                        sha256: sha256.clone(),
                    },
                );
            }
        }

        processing_queue.remove(&path_str);
    }
}

fn apply_policy(path: &Path, quarantine_dir: &str, classification: &str) {
    match classification {
        "malicious" => {
            info!("policy_action action=quarantine classification=malicious path={:?}", path);
            policy_engine::enforce_quarantine(path, quarantine_dir);
        }
        "suspicious" => {
            info!("policy_action action=alert classification=suspicious path={:?}", path);
        }
        _ => {
            info!("policy_action action=allow classification=benign path={:?}", path);
        }
    }
}

async fn flush_offline_queue(
    api: &api_client::AgentApiClient,
    queue_path: &str,
    cache: &mut scanner::LocalCache,
    quarantine_dir: &str,
) -> Result<(), String> {
    let events = offline_queue::load_all(queue_path);
    if events.is_empty() {
        return Ok(());
    }

    let mut remaining = Vec::new();
    for event in events {
        let event_path = Path::new(&event.path);
        if !event_path.exists() {
            continue;
        }

        match api.lookup_hash(&event.sha256).await {
            Ok(Some(verdict)) => {
                cache.insert(event.sha256.clone(), verdict.clone());
                apply_policy(event_path, quarantine_dir, &verdict.classification);
            }
            Ok(None) => {
                remaining.push(event);
            }
            Err(_) => {
                remaining.push(event);
            }
        }
    }

    offline_queue::rewrite(queue_path, &remaining)
}
