use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher, EventKind};
use tokio::sync::mpsc;
use std::path::PathBuf;
use log::{info, error};

pub fn start_monitoring(target_path: &str, tx: mpsc::Sender<PathBuf>) -> notify::Result<RecommendedWatcher> {
    let tx_clone = tx.clone();
    
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<Event>| {
        match res {
            Ok(event) => {
                // Focus on CloseWrite to avoid hashing partially downloaded files
                // Fallback to Create for immediate triggers
                match event.kind {
                    EventKind::Access(notify::event::AccessKind::Close(notify::event::AccessMode::Write)) |
                    EventKind::Create(_) => {
                        for path in event.paths {
                            if path.is_file() {
                                // Blocking send is okay inside the notify synchronous callback
                                if let Err(e) = tx_clone.blocking_send(path.clone()) {
                                    error!("Failed to send path to processing channel: {}", e);
                                }
                            }
                        }
                    },
                    _ => {} // Ignore read, delete, open events
                }
            },
            Err(e) => error!("Watch error: {:?}", e),
        }
    })?;

    info!("Starting recursive file monitor on: {}", target_path);
    watcher.watch(std::path::Path::new(target_path), RecursiveMode::Recursive)?;

    Ok(watcher)
}
