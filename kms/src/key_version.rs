use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyVersionInfo {
    pub current_version: u32,
    pub active_version: u32,
    pub rotation_in_progress: bool,
    pub rotation_deadline: Option<u64>,        // Unix timestamp
    pub version_created_at: HashMap<u32, u64>, // version -> timestamp
}

impl KeyVersionInfo {
    pub fn new(initial_version: u32) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut version_created_at = HashMap::new();
        version_created_at.insert(initial_version, now);

        Self {
            current_version: initial_version,
            active_version: initial_version,
            rotation_in_progress: false,
            rotation_deadline: None,
            version_created_at,
        }
    }

    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            // Default to version 1 if file doesn't exist (backward compatibility)
            return Ok(Self::new(1));
        }
        let content = std::fs::read_to_string(path).context("Failed to read key version file")?;
        let mut info: Self =
            serde_json::from_str(&content).context("Failed to parse key version file")?;

        // Auto-fix: If rotation is in progress but current_version == active_version,
        // it means rotation was completed but state wasn't saved properly
        if info.rotation_in_progress && info.current_version == info.active_version {
            tracing::info!(
                "Auto-fixing rotation state: rotation was completed but state wasn't saved"
            );
            info.rotation_in_progress = false;
            info.rotation_deadline = None;
            // Save the fixed state
            if let Err(e) = info.save(path) {
                tracing::warn!("Failed to save fixed key version state: {}", e);
            }
        }

        // Auto-fix: If rotation is in progress but deadline has passed,
        // automatically complete the rotation
        if info.rotation_in_progress {
            if let Some(deadline) = info.rotation_deadline {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                if now > deadline {
                    tracing::info!("Auto-completing rotation: grace period has expired");
                    info.complete_rotation();
                    if let Err(e) = info.save(path) {
                        tracing::warn!("Failed to save completed rotation state: {}", e);
                    }
                }
            }
        }

        Ok(info)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let content =
            serde_json::to_string_pretty(self).context("Failed to serialize key version info")?;
        std::fs::write(path, content).context("Failed to write key version file")?;
        Ok(())
    }

    pub fn start_rotation(&mut self, new_version: u32, grace_period_days: u64) -> Result<()> {
        if self.rotation_in_progress {
            anyhow::bail!("Rotation already in progress1");
        }
        if new_version <= self.current_version {
            anyhow::bail!("New version must be greater than current version");
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let deadline = now + (grace_period_days * 24 * 60 * 60);

        self.current_version = new_version;
        self.rotation_in_progress = true;
        self.rotation_deadline = Some(deadline);
        self.version_created_at.insert(new_version, now);

        Ok(())
    }

    pub fn complete_rotation(&mut self) {
        self.active_version = self.current_version;
        self.rotation_in_progress = false;
        self.rotation_deadline = None;
    }

    pub fn is_version_active(&self, version: u32) -> bool {
        if version == self.active_version {
            return true;
        }
        if self.rotation_in_progress && version == self.current_version {
            return true;
        }
        false
    }

    pub fn is_version_deprecated(&self, version: u32) -> bool {
        if !self.rotation_in_progress {
            return false;
        }
        if let Some(deadline) = self.rotation_deadline {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if now > deadline {
                return version < self.current_version;
            }
        }
        false
    }
}
