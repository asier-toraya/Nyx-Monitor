use std::collections::HashSet;
use std::process::Command;

#[derive(Debug, Clone)]
pub struct NetworkConnection {
    pub protocol: String,
    pub local_address: String,
    pub remote_address: String,
    pub state: Option<String>,
    pub pid: u32,
}

impl NetworkConnection {
    pub fn key(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}",
            self.protocol.to_lowercase(),
            self.local_address.to_lowercase(),
            self.remote_address.to_lowercase(),
            self.state.as_deref().unwrap_or_default().to_lowercase(),
            self.pid
        )
    }
}

pub fn collect_connections() -> Result<Vec<NetworkConnection>, String> {
    let mut command = Command::new("netstat");
    command.args(["-ano"]);

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }

    let output = command
        .output()
        .map_err(|err| format!("failed collecting netstat output: {err}"))?;
    if !output.status.success() {
        return Err("netstat command failed".to_string());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut rows = Vec::new();
    let mut seen = HashSet::new();

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !(trimmed.starts_with("TCP") || trimmed.starts_with("UDP")) {
            continue;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }

        if parts[0].eq_ignore_ascii_case("TCP") {
            if parts.len() < 5 {
                continue;
            }
            let pid = match parts[4].parse::<u32>() {
                Ok(value) => value,
                Err(_) => continue,
            };
            let connection = NetworkConnection {
                protocol: "tcp".to_string(),
                local_address: parts[1].to_string(),
                remote_address: parts[2].to_string(),
                state: Some(parts[3].to_string()),
                pid,
            };
            if seen.insert(connection.key()) {
                rows.push(connection);
            }
            continue;
        }

        let pid = match parts.last().and_then(|value| value.parse::<u32>().ok()) {
            Some(value) => value,
            None => continue,
        };
        let remote = if parts.len() > 3 { parts[2] } else { "*:*" };
        let connection = NetworkConnection {
            protocol: "udp".to_string(),
            local_address: parts[1].to_string(),
            remote_address: remote.to_string(),
            state: None,
            pid,
        };
        if seen.insert(connection.key()) {
            rows.push(connection);
        }
    }

    Ok(rows)
}
