use std::collections::HashMap;
use std::process::Command;

use regex::Regex;

pub fn collect_gpu_usage_by_pid() -> HashMap<u32, f32> {
    let mut usage_by_pid: HashMap<u32, f32> = HashMap::new();

    let script = "$ErrorActionPreference='SilentlyContinue'; Get-Counter '\\GPU Engine(*)\\Utilization Percentage' | Select-Object -ExpandProperty CounterSamples | ForEach-Object { \"{0}|{1}\" -f $_.InstanceName, $_.CookedValue }";
    let mut command = Command::new("powershell.exe");
    command.args(["-NoProfile", "-Command", script]);
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let output = command.output();

    let Ok(output) = output else {
        return usage_by_pid;
    };
    if !output.status.success() {
        return usage_by_pid;
    }

    let Ok(pid_regex) = Regex::new(r"pid_(\d+)") else {
        return usage_by_pid;
    };

    let raw = String::from_utf8_lossy(&output.stdout);
    for line in raw.lines() {
        let mut parts = line.split('|');
        let instance = parts.next().unwrap_or_default();
        let value = parts
            .next()
            .unwrap_or_default()
            .trim()
            .parse::<f32>()
            .unwrap_or(0.0);

        if value <= 0.0 {
            continue;
        }

        let pid = pid_regex
            .captures(instance)
            .and_then(|caps| caps.get(1))
            .and_then(|m| m.as_str().parse::<u32>().ok());

        if let Some(pid) = pid {
            usage_by_pid
                .entry(pid)
                .and_modify(|current| *current += value)
                .or_insert(value);
        }
    }

    for value in usage_by_pid.values_mut() {
        *value = value.clamp(0.0, 100.0);
    }

    usage_by_pid
}
