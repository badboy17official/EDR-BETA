use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuedEvent {
    pub path: String,
    pub sha256: String,
}

pub fn enqueue(path: &str, event: &QueuedEvent) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| e.to_string())?;

    let line = serde_json::to_string(event).map_err(|e| e.to_string())?;
    file.write_all(line.as_bytes()).map_err(|e| e.to_string())?;
    file.write_all(b"\n").map_err(|e| e.to_string())?;
    Ok(())
}

pub fn load_all(path: &str) -> Vec<QueuedEvent> {
    let file = match OpenOptions::new().read(true).open(path) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };

    let reader = BufReader::new(file);
    reader
        .lines()
        .filter_map(|line| line.ok())
        .filter_map(|line| serde_json::from_str::<QueuedEvent>(&line).ok())
        .collect()
}

pub fn rewrite(path: &str, events: &[QueuedEvent]) -> Result<(), String> {
    let mut tmp = String::new();
    for event in events {
        let line = serde_json::to_string(event).map_err(|e| e.to_string())?;
        tmp.push_str(&line);
        tmp.push('\n');
    }
    fs::write(path, tmp).map_err(|e| e.to_string())
}
