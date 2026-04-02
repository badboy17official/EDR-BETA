use std::path::Path;
use std::fs;
use std::process::Command;
use log::{info, error, warn};

pub fn enforce_quarantine(file_path: &Path, quarantine_dir: &str) {
    if !file_path.exists() {
        return;
    }
    
    let file_name = match file_path.file_name() {
        Some(name) => name,
        None => return,
    };
    
    let dest = Path::new(quarantine_dir).join(file_name);
    
    info!("Policy Engine: Blocking and Quarantining file to {:?}", dest);
    
    // Move the file out of the user's reach
    if let Err(e) = fs::rename(file_path, &dest) {
        error!("Failed to quarantine file {:?}: {}", file_path, e);
        // Fallback: try to forcefully remove it if rename fails across mount points
        if let Err(rm_err) = fs::remove_file(file_path) {
            error!("Failed fallback deletion for {:?}: {}", file_path, rm_err);
        } else {
            warn!("File deleted instead of moved due to boundary issues: {:?}", file_path);
        }
    } else {
        // Strip execution permissions in quarantine
        // In Rust, cross-platform permissions require std::os::unix::fs::PermissionsExt
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(mut perms) = fs::metadata(&dest).map(|m| m.permissions()) {
                perms.set_mode(0o600); // read/write only, no execute
                let _ = fs::set_permissions(&dest, perms);
            }
        }
    }

    // Best-effort process kill for binaries executed from original path.
    // This is path-based and may not catch all execution flows.
    if let Some(path_str) = file_path.to_str() {
        let _ = Command::new("pkill")
            .arg("-f")
            .arg(path_str)
            .status();
    }
    
    // Note: Killing the specific process that created the file without eBPF/fanotify PID attribution 
    // requires walking /proc or using sysinfo to match exact binary paths.
    // For Phase 5, quarantine safely handles the file propagation threat.
}
