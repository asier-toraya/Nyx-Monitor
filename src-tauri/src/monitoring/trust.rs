use crate::models::TrustLevel;

const TRUSTED_PUBLISHERS: &[&str] = &[
    "microsoft",
    "google",
    "mozilla",
    "adobe",
    "intel",
    "nvidia",
    "amd",
    "oracle",
    "vmware",
    "docker",
    "github",
    "valve",
    "electronic arts",
    "epic games",
    "jetbrains",
];

pub fn classify_process_trust(path: Option<&str>, is_signed: Option<bool>) -> TrustLevel {
    if is_windows_path(path) {
        return TrustLevel::WindowsNative;
    }

    if is_signed == Some(true) {
        return TrustLevel::Trusted;
    }

    TrustLevel::Unknown
}

pub fn classify_program_trust(
    name: &str,
    publisher: Option<&str>,
    install_location: Option<&str>,
    executable_path: Option<&str>,
) -> TrustLevel {
    let _ = name;
    if is_windows_path(executable_path) || is_windows_path(install_location) {
        return TrustLevel::WindowsNative;
    }

    let normalized_publisher = publisher.unwrap_or_default().to_lowercase();
    if TRUSTED_PUBLISHERS
        .iter()
        .any(|candidate| normalized_publisher.contains(candidate))
    {
        return TrustLevel::Trusted;
    }

    TrustLevel::Unknown
}

pub fn is_windows_path(path: Option<&str>) -> bool {
    let lower = path.unwrap_or_default().to_lowercase();
    lower.starts_with("c:\\windows\\")
        || lower.starts_with("\\\\?\\c:\\windows\\")
        || lower.contains("\\windows\\system32\\")
        || lower.contains("\\windows\\syswow64\\")
}

pub fn extract_executable_from_command(command: &str) -> Option<String> {
    let raw = command.trim();
    if raw.is_empty() {
        return None;
    }

    let cleaned = raw
        .split_once(',')
        .map(|(prefix, _)| prefix.trim())
        .unwrap_or(raw);

    if let Some(rest) = cleaned.strip_prefix('"') {
        if let Some(end) = rest.find('"') {
            return Some(rest[..end].to_string());
        }
    }

    cleaned
        .split_whitespace()
        .next()
        .map(|value| value.trim_matches('"').to_string())
}

pub fn normalize_key(value: &str) -> Option<String> {
    let mut normalized = value.trim().trim_matches('"').to_lowercase();
    if let Some(stripped) = normalized.strip_prefix("\\\\?\\") {
        normalized = stripped.to_string();
    }
    normalized = normalized.replace('/', "\\");
    if normalized.is_empty() {
        return None;
    }
    Some(normalized)
}

pub fn process_match_keys(path: Option<&str>, name: &str) -> Vec<String> {
    let mut keys = Vec::new();
    if let Some(path_key) = normalize_key(path.unwrap_or_default()) {
        keys.push(path_key);
    }
    if let Some(name_key) = normalize_key(name) {
        keys.push(name_key);
    }
    keys
}

pub fn program_primary_key(executable_path: Option<&str>, install_location: Option<&str>, name: &str) -> String {
    normalize_key(executable_path.unwrap_or_default())
        .or_else(|| normalize_key(install_location.unwrap_or_default()))
        .or_else(|| normalize_key(name))
        .unwrap_or_else(|| "unknown-program".to_string())
}

pub fn program_match_keys(executable_path: Option<&str>, install_location: Option<&str>, name: &str) -> Vec<String> {
    let mut keys = Vec::new();
    if let Some(key) = normalize_key(executable_path.unwrap_or_default()) {
        keys.push(key);
    }
    if let Some(key) = normalize_key(install_location.unwrap_or_default()) {
        keys.push(key);
    }
    if let Some(key) = normalize_key(name) {
        keys.push(key);
    }
    keys
}
