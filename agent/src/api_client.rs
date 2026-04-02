use reqwest::{Client, multipart};
use tokio::time::{sleep, Duration};
use std::path::Path;
use log::{error, debug};
use serde_json::Value;

use crate::config::Config;
use crate::scanner::Verdict;

#[derive(Clone)]
pub struct AgentApiClient {
    client: Client,
    config: Config,
}

impl AgentApiClient {
    pub fn new(config: Config) -> Self {
        Self {
            client: Client::new(),
            config,
        }
    }

    /// Uploads a file to the backend with basic retry logic
    pub async fn upload_file(&self, path: &Path) -> Result<String, String> {
        let max_retries = 3;
        let mut retry_count = 0;
        
        // Fast HTTP client bound loop
        loop {
            match self.try_upload_file(path).await {
                Ok(task_id) => return Ok(task_id),
                Err(e) => {
                    retry_count += 1;
                    if retry_count >= max_retries {
                        error!("Failed to upload {:?} after {} attempts: {}", path, max_retries, e);
                        return Err(e);
                    }
                    debug!("Upload retry {} for {:?}", retry_count, path);
                    sleep(Duration::from_secs(2)).await;
                }
            }
        }
    }

    pub async fn lookup_hash(&self, sha256: &str) -> Result<Option<Verdict>, String> {
        let url = format!("{}/hash/{}", self.config.api_url, sha256);
        let response = self
            .client
            .get(&url)
            .header("X-Agent-Key", &self.config.api_key)
            .header("X-Agent-ID", &self.config.agent_id)
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if !response.status().is_success() {
            return Err(format!("Hash lookup failed: {}", response.status()));
        }

        let json: Value = response.json().await.map_err(|e| e.to_string())?;
        if json["status"] != "success" {
            return Ok(None);
        }

        let found = json["data"]["found"].as_bool().unwrap_or(false);
        if !found {
            return Ok(None);
        }

        let classification = json["data"]["classification"]
            .as_str()
            .unwrap_or("benign")
            .to_string();
        let risk_score = json["data"]["risk_score"].as_f64().unwrap_or(0.0);
        Ok(Some(Verdict {
            classification,
            risk_score,
        }))
    }

    async fn try_upload_file(&self, path: &Path) -> Result<String, String> {
        let file_name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
        
        let file_bytes = std::fs::read(path).map_err(|e| e.to_string())?;
        let part = multipart::Part::bytes(file_bytes).file_name(file_name);
        let form = multipart::Form::new().part("file", part);
        
        let url = format!("{}/upload", self.config.api_url);
        
        let response = self.client.post(&url)
            .header("X-Agent-Key", &self.config.api_key)
            .header("X-Agent-ID", &self.config.agent_id)
            .multipart(form)
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if !response.status().is_success() {
            return Err(format!("Backend error: {}", response.status()));
        }

        let json: Value = response.json().await.map_err(|e| e.to_string())?;
        if json["status"] == "success" {
            let task_id = json["data"]["task_id"].as_str().unwrap_or_default().to_string();
            Ok(task_id)
        } else {
            Err("Backend returned error status".to_string())
        }
    }

    /// Polls backend with exponential backoff to reduce API spam.
    pub async fn poll_task_status(&self, task_id: &str) -> Option<Verdict> {
        let url = format!("{}/report/{}", self.config.api_url, task_id);

        let mut delay_secs = 2u64;
        for _ in 0..8 {
            sleep(Duration::from_secs(delay_secs)).await;
            delay_secs = (delay_secs * 2).min(12);
            
            if let Ok(resp) = self.client.get(&url)
                .header("X-Agent-Key", &self.config.api_key)
                .header("X-Agent-ID", &self.config.agent_id)
                .send()
                .await 
            {
                if let Ok(json) = resp.json::<Value>().await {
                    let status = json["data"]["status"].as_str().unwrap_or("");
                    if status == "COMPLETED" {
                        let classification = json["data"]["classification"]
                            .as_str()
                            .unwrap_or("benign")
                            .to_string();
                        let risk_score = json["data"]["risk_score"].as_f64().unwrap_or(0.0);
                        return Some(Verdict { classification, risk_score });
                    }
                    if status == "FAILED" {
                        return None;
                    }
                }
            }
        }
        
        None // Timeout
    }
}
