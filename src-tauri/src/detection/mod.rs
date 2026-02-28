use chrono::Utc;

use crate::models::{
    Alert, AlertSeverity, AlertStatus, DetectionProfile, ProcessMetric, RiskLevel,
    SuspicionAssessment,
};

const SCRIPT_HOSTS: &[&str] = &[
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "rundll32.exe",
    "mshta.exe",
];

const OFFICE_PARENTS: &[&str] = &[
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "acrord32.exe",
];

pub fn assess_process(
    metric: &ProcessMetric,
    parent_name: Option<&str>,
    is_signed: Option<bool>,
    cpu_spike: bool,
    profile: &DetectionProfile,
) -> SuspicionAssessment {
    let mut reasons = Vec::new();
    let mut score: u8 = 0;
    let name = metric.name.to_lowercase();
    let parent = parent_name.unwrap_or_default().to_lowercase();

    if let Some(path) = &metric.exe_path {
        let path_lower = path.to_lowercase();
        if path_lower.contains("\\appdata\\local\\temp")
            || path_lower.contains("\\windows\\temp")
            || path_lower.contains("\\temp\\")
        {
            score = score.saturating_add(45);
            reasons.push("Executable running from temporary directory".to_string());
        }

        if path_lower.contains("\\appdata\\roaming\\")
            && SCRIPT_HOSTS.iter().any(|host| host == &name)
        {
            score = score.saturating_add(30);
            reasons.push("Script host launched from roaming profile path".to_string());
        }
    }

    if SCRIPT_HOSTS.iter().any(|host| host == &name) && OFFICE_PARENTS.iter().any(|p| p == &parent) {
        score = score.saturating_add(40);
        reasons.push("Suspicious parent-child relation: office app spawning script host".to_string());
    }

    if is_signed == Some(false) {
        score = score.saturating_add(35);
        reasons.push("Binary is unsigned or signature is invalid".to_string());
    }

    if cpu_spike {
        score = score.saturating_add(25);
        reasons.push("Sustained CPU spike above baseline".to_string());
    }

    let (suspicious_threshold, unknown_threshold) = match profile {
        DetectionProfile::Conservative => (85, 45),
        DetectionProfile::Balanced => (70, 35),
        DetectionProfile::Aggressive => (55, 25),
    };

    let level = if score >= suspicious_threshold {
        RiskLevel::Suspicious
    } else if score >= unknown_threshold {
        RiskLevel::Unknown
    } else {
        RiskLevel::Legitimate
    };

    let confidence = ((score as f32) / 100.0).clamp(0.1, 0.99);
    SuspicionAssessment {
        level,
        score,
        reasons,
        confidence,
    }
}

pub fn build_alert(metric: &ProcessMetric, assessment: &SuspicionAssessment, cpu_spike: bool) -> Option<Alert> {
    if assessment.level != RiskLevel::Suspicious && !cpu_spike {
        return None;
    }

    let (severity, title, description, alert_type) = if cpu_spike {
        (
            AlertSeverity::Warn,
            format!("High CPU sustained in {}", metric.name),
            format!(
                "Process {} (PID {}) exceeded configured CPU threshold for multiple samples",
                metric.name, metric.pid
            ),
            "cpu_spike".to_string(),
        )
    } else {
        (
            AlertSeverity::Critical,
            format!("Suspicious process detected: {}", metric.name),
            format!(
                "Process {} (PID {}) matched conservative suspicious behavior rules",
                metric.name, metric.pid
            ),
            "suspicious_process".to_string(),
        )
    };

    Some(Alert {
        id: format!("{}-{}-{}", alert_type, metric.pid, Utc::now().timestamp_millis()),
        alert_type,
        severity,
        pid: Some(metric.pid),
        title,
        description,
        evidence: assessment.reasons.clone(),
        timestamp: Utc::now().to_rfc3339(),
        status: AlertStatus::Active,
    })
}
