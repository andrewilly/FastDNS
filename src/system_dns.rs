#![allow(dead_code)]
use std::process::Command;

#[cfg(target_os = "macos")]
#[allow(dead_code)]
pub fn install_service(plist_path: &str) -> Result<(), String> {
    // First unload if already loaded (ignore errors)
    let _ = Command::new("launchctl")
        .args(["unload", plist_path])
        .status();
    // Then load (compatible with SIP on macOS 15+)
    let status = Command::new("launchctl")
        .args(["load", "-w", plist_path])
        .status()
        .map_err(|e| format!("Failed to run launchctl load: {}", e))?;

    if !status.success() {
        return Err("launchctl load failed".to_string());
    }
    Ok(())
}

#[cfg(target_os = "windows")]
#[allow(dead_code)]
pub fn install_service(_plist_path: &str) -> Result<(), String> {
    let exe_path = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "fastdns.exe".to_string());
    let bin_path = format!("\"{}\" -b 127.0.0.1:53 -c 250000 --dnssec", exe_path);
    let status = Command::new("sc")
        .args([
            "create",
            "FastDNS",
            "binPath=",
            &bin_path,
            "start=",
            "auto",
            "DisplayName=",
            "FastDNS Recursive Resolver",
            "type=",
            "own",
            "error=",
            "normal",
        ])
        .status()
        .map_err(|e| format!("Failed to create Windows service: {}", e))?;
    if !status.success() {
        return Err("sc create failed. Run as Administrator.".to_string());
    }
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
#[allow(dead_code)]
pub fn install_service(_plist_path: &str) -> Result<(), String> {
    Err("Automatic service installation not supported on this platform".to_string())
}

#[cfg(target_os = "macos")]
pub fn uninstall_service(plist_path: &str) -> Result<(), String> {
    // Note: just use unload — bootout system fails with EIO on macOS 15+ SIP
    let status = Command::new("launchctl")
        .args(["unload", plist_path])
        .status()
        .map_err(|e| format!("Failed to run launchctl unload: {}", e))?;

    if !status.success() {
        return Err("launchctl unload failed".to_string());
    }
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn uninstall_service(_plist_path: &str) -> Result<(), String> {
    let _ = Command::new("sc").args(["stop", "FastDNS"]).status();
    let status = Command::new("sc")
        .args(["delete", "FastDNS"])
        .status()
        .map_err(|e| format!("Failed to remove Windows service: {}", e))?;
    if !status.success() {
        return Err("sc delete failed. Run as Administrator.".to_string());
    }
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub fn uninstall_service(_plist_path: &str) -> Result<(), String> {
    Err("Automatic service uninstall not supported on this platform".to_string())
}

#[cfg(target_os = "macos")]
pub fn set_system_dns(dns_server: &str) -> Result<(), String> {
    let services = get_network_services_macos()?;
    for service in services {
        Command::new("networksetup")
            .args(["-setdnsservers", &service, dns_server])
            .status()
            .map_err(|e| format!("Failed to set DNS for {}: {}", service, e))?;
    }
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn set_system_dns(dns_server: &str) -> Result<(), String> {
    // On Windows, set DNS via netsh
    let status = Command::new("netsh")
        .args([
            "interface",
            "ip",
            "set",
            "dns",
            "name=\"Local Area Connection\"",
            "static",
            dns_server,
        ])
        .status()
        .map_err(|e| format!("Failed to set system DNS: {}", e))?;
    if !status.success() {
        // Try with different interface name
        let _ = Command::new("netsh")
            .args([
                "interface",
                "ip",
                "set",
                "dns",
                "name=\"Ethernet\"",
                "static",
                dns_server,
            ])
            .status();
    }
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub fn set_system_dns(_dns_server: &str) -> Result<(), String> {
    Err("Automatic DNS configuration not supported on this platform".to_string())
}

#[cfg(target_os = "macos")]
fn get_network_services_macos() -> Result<Vec<String>, String> {
    let output = Command::new("networksetup")
        .arg("-listallnetworkservices")
        .output()
        .map_err(|e| format!("Failed to list network services: {}", e))?;

    let text = String::from_utf8_lossy(&output.stdout);
    Ok(text
        .lines()
        .skip(1)
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect())
}
