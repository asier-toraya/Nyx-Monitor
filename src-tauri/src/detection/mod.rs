use chrono::Utc;

use crate::models::{
    Alert, AlertSeverity, AlertStatus, DetectionProfile, ProcessMetric, RiskLevel,
    SuspicionAssessment, ThreatVerdict, TrustLevel,
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
        score = score.saturating_add(12);
        reasons.push("Sustained CPU spike above baseline (performance anomaly)".to_string());
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

pub fn classify_threat_verdict(
    score: u8,
    base_level: &RiskLevel,
    trust_level: &TrustLevel,
    correlation_count: usize,
    internal_process: bool,
) -> ThreatVerdict {
    if internal_process {
        return ThreatVerdict::Benign;
    }

    if *base_level == RiskLevel::Legitimate {
        if score >= 55 {
            return ThreatVerdict::LowRisk;
        }
        return ThreatVerdict::Benign;
    }

    let untrusted = *trust_level == TrustLevel::Unknown;
    if score >= 95 && *base_level == RiskLevel::Suspicious && untrusted && correlation_count >= 2 {
        return ThreatVerdict::ConfirmedMalicious;
    }
    if score >= 86 && *base_level == RiskLevel::Suspicious && untrusted && correlation_count >= 1 {
        return ThreatVerdict::LikelyMalicious;
    }
    if score >= 70 && *base_level == RiskLevel::Suspicious {
        return ThreatVerdict::Suspicious;
    }
    if score >= 35 {
        return ThreatVerdict::LowRisk;
    }
    ThreatVerdict::Benign
}

pub fn compute_risk_score(base_score: u8, correlation_bonuses: &[u8]) -> u8 {
    let correlation_total: u16 = correlation_bonuses
        .iter()
        .map(|bonus| *bonus as u16)
        .sum::<u16>()
        .min(22);
    let total = (base_score as u16).saturating_add(correlation_total);
    total.min(100) as u8
}

pub fn build_correlated_alert(
    metric: &ProcessMetric,
    score: u8,
    verdict: &ThreatVerdict,
    correlation_reasons: &[String],
) -> Option<Alert> {
    if score < 88
        || correlation_reasons.len() < 2
        || metric.suspicion.level != RiskLevel::Suspicious
        || metric.trust_level != TrustLevel::Unknown
    {
        return None;
    }

    let severity = if score >= 90 {
        AlertSeverity::Critical
    } else {
        AlertSeverity::Warn
    };

    let mut evidence = metric.suspicion.reasons.clone();
    evidence.extend(correlation_reasons.iter().cloned());
    evidence.push(format!("Risk score: {}", score));
    evidence.push(format!("Verdict: {:?}", verdict));

    Some(Alert {
        id: format!("correlated_threat-{}-{}", metric.pid, Utc::now().timestamp_millis()),
        alert_type: "correlated_threat".to_string(),
        severity,
        pid: Some(metric.pid),
        title: format!("Correlated threat signal in {}", metric.name),
        description: format!(
            "Correlated signals raised {} (PID {}) to score {} with verdict {:?}",
            metric.name, metric.pid, score, verdict
        ),
        evidence,
        timestamp: Utc::now().to_rfc3339(),
        status: AlertStatus::Active,
    })
}
