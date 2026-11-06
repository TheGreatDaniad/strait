//! Remote Access Module
//!
//! Session management and address/password assignment for
//! Anydesk-style remote access between two devices.

use std::collections::HashMap;
use std::time::Instant;

/// Device Configuration
#[derive(Debug, Clone)]
pub struct DeviceConfig {
    pub device_id: String,
    pub device_name: String,
    pub port: u16,
    pub max_connections: u32,
}

/// A remote access session
#[derive(Debug, Clone)]
pub struct Session {
    pub session_id: String,
    pub remote_device_id: String,
    pub remote_address: String,
    pub remote_port: u16,
    pub password: String,
    pub created_at: Instant,
    pub is_active: bool,
}

impl Session {
    /// Check a connect password without short-circuiting.
    pub fn matches_password(&self, candidate: &str) -> bool {
        let (a, b) = (self.password.as_bytes(), candidate.as_bytes());
        if a.len() != b.len() {
            return false;
        }
        let mut diff = 0u8;
        for (x, y) in a.iter().zip(b) {
            diff |= x ^ y;
        }
        diff == 0
    }
}

/// Remote Access Module
#[derive(Clone)]
pub struct RemoteAccessModule {
    device_config: DeviceConfig,
    sessions: HashMap<String, Session>,
    total_connections: usize,
}

impl RemoteAccessModule {
    pub fn new(config: DeviceConfig) -> Self {
        Self {
            device_config: config,
            sessions: HashMap::new(),
            total_connections: 0,
        }
    }

    pub fn from_config(cfg: &crate::config::RemoteAccessConfig) -> Self {
        Self::new(DeviceConfig {
            device_id: cfg.device_id.clone(),
            device_name: cfg.device_name.clone(),
            port: cfg.port,
            max_connections: cfg.max_connections,
        })
    }

    /// Create a new (inactive) remote access session with a one-time password.
    pub fn create_session(
        &mut self,
        remote_device_id: &str,
        remote_address: &str,
        remote_port: u16,
    ) -> Session {
        let session = Session {
            session_id: format!("sess_{}", uuid::Uuid::new_v4()),
            remote_device_id: remote_device_id.to_string(),
            remote_address: remote_address.to_string(),
            remote_port,
            password: generate_secure_password(),
            created_at: Instant::now(),
            is_active: false,
        };
        self.sessions
            .insert(session.session_id.clone(), session.clone());
        session
    }

    pub fn get_active_sessions(&self) -> Vec<&Session> {
        self.sessions.values().filter(|s| s.is_active).collect()
    }

    /// Activate a session. Returns None if the id is unknown.
    pub fn start_session(&mut self, session_id: &str) -> Option<Session> {
        let session = self.sessions.get_mut(session_id)?;
        if !session.is_active {
            session.is_active = true;
            self.total_connections += 1;
        }
        Some(session.clone())
    }

    pub fn stop_session(&mut self, session_id: &str) {
        if let Some(session) = self.sessions.get_mut(session_id) {
            session.is_active = false;
        } else {
            log::warn!("session not found: {}", session_id);
        }
    }

    pub fn get_connection_stats(&self) -> ConnectionStats {
        ConnectionStats {
            total_sessions: self.sessions.len(),
            active_sessions: self.sessions.values().filter(|s| s.is_active).count(),
            total_connections: self.total_connections,
        }
    }

    pub fn get_device_info(&self) -> DeviceInfo {
        DeviceInfo {
            device_id: self.device_config.device_id.clone(),
            device_name: self.device_config.device_name.clone(),
            port: self.device_config.port,
            max_connections: self.device_config.max_connections,
        }
    }

    /// Local interface address (no external server needed).
    pub async fn discover_address(&self) -> Result<(String, u16), Box<dyn std::error::Error>> {
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect("8.8.8.8:80").await?;
        Ok((
            socket.local_addr()?.ip().to_string(),
            self.device_config.port,
        ))
    }
}

/// Connection Statistics
#[derive(Debug, Clone)]
pub struct ConnectionStats {
    pub total_sessions: usize,
    pub active_sessions: usize,
    pub total_connections: usize,
}

/// Device Info
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub device_id: String,
    pub device_name: String,
    pub port: u16,
    pub max_connections: u32,
}

fn generate_secure_password() -> String {
    // 16 hex chars of UUID entropy, prefixed for readability.
    format!("pass_{}", &uuid::Uuid::new_v4().simple().to_string()[..16])
}
