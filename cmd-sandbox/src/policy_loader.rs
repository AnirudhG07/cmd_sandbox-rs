// Policy Loading Module
// This module handles populating eBPF maps with policy configurations

use aya::{Ebpf, maps::Array};
use cmd_sandbox_common::policy_shared::{NetworkPolicy, FilesystemPolicy};
use crate::policy::PolicyConfig;
use std::fs;

/// Populate network policy eBPF map with configuration
pub fn populate_network_policy(ebpf: &mut Ebpf, config: &PolicyConfig) -> anyhow::Result<()> {
    let mut network_policy_map: Array<_, NetworkPolicy> = 
        Array::try_from(ebpf.map_mut("NETWORK_POLICY").unwrap())?;

    // Create network policy struct from config
    let mut allowed_ports = [0u16; 10];
    let num_ports = config.network_policies.allowed_ports.len().min(10);
    
    for (i, &port) in config.network_policies.allowed_ports.iter().take(10).enumerate() {
        allowed_ports[i] = port;
    }

    let policy = NetworkPolicy {
        allowed_ports,
        num_ports: num_ports as u32,
        block_private_ips: if config.network_policies.block_private_ips { 1 } else { 0 },
        max_connections: config.network_policies.max_connections,
        connection_timeout: config.network_policies.connection_timeout,
    };

    // Write policy to map
    network_policy_map.set(0, policy, 0)?;
    
    println!("✓ Network policy loaded into eBPF map:");
    println!("  Allowed ports: {:?}", &allowed_ports[..num_ports]);
    println!("  Block private IPs: {}", config.network_policies.block_private_ips);
    println!("  Max connections: {}", config.network_policies.max_connections);
    
    // Populate whitelisted IPs from allowed domains
    populate_whitelisted_ips(ebpf, config)?;
    
    Ok(())
}

/// Resolve whitelisted domains to IPs and populate the eBPF map
pub fn populate_whitelisted_ips(ebpf: &mut Ebpf, config: &PolicyConfig) -> anyhow::Result<()> {
    use std::net::ToSocketAddrs;
    use aya::maps::HashMap;
    
    let mut whitelist_map: HashMap<_, u32, u8> = 
        HashMap::try_from(ebpf.map_mut("WHITELISTED_IPS").unwrap())?;
    
    println!("✓ Resolving and whitelisting domains:");
    
    for domain in &config.network_policies.allowed_domains {
        // Resolve domain to IPs using DNS
        // We use port 443 as a dummy port for resolution
        let addr_string = format!("{}:443", domain);
        
        match addr_string.to_socket_addrs() {
            Ok(addrs) => {
                for addr in addrs {
                    if let std::net::IpAddr::V4(ipv4) = addr.ip() {
                        let ip_u32 = u32::from(ipv4);
                        // Convert to network byte order (big-endian) to match what eBPF sees
                        let ip_be = ip_u32.to_be();
                        
                        whitelist_map.insert(ip_be, 1u8, 0)?;
                        println!("  {} -> {} (0x{:08x})", domain, ipv4, ip_be);
                    }
                }
            }
            Err(e) => {
                eprintln!("  ⚠️  Failed to resolve {}: {}", domain, e);
            }
        }
    }
    
    Ok(())
}

/// Populate filesystem policy eBPF map with configuration
/// Returns the allowed write path for further filesystem setup
pub fn populate_filesystem_policy(ebpf: &mut Ebpf, config: &PolicyConfig) -> anyhow::Result<String> {
    let mut fs_policy_map: Array<_, FilesystemPolicy> = 
        Array::try_from(ebpf.map_mut("FILESYSTEM_POLICY").unwrap())?;
    
    // Get the first allowed write directory from config
    let allowed_path = if !config.filesystem_policies.allowed_write_dirs.is_empty() {
        config.filesystem_policies.allowed_write_dirs[0].clone()
    } else {
        "/tmp/curl_downloads/".to_string()
    };
    
    // Create the directory if it doesn't exist
    let _ = fs::create_dir_all(&allowed_path);
    
    // Set permissions to 0777 (rwxrwxrwx) so all users can write
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = fs::metadata(&allowed_path) {
            let mut perms = metadata.permissions();
            perms.set_mode(0o777);
            let _ = fs::set_permissions(&allowed_path, perms);
        }
    }
    
    // Create filesystem policy
    let mut policy = FilesystemPolicy {
        allowed_write_path: [0u8; 256],
        path_len: allowed_path.len() as u32,
    };
    
    // Copy the path bytes
    let path_bytes = allowed_path.as_bytes();
    for (i, &byte) in path_bytes.iter().enumerate() {
        if i < 256 {
            policy.allowed_write_path[i] = byte;
        }
    }
    
    fs_policy_map.set(0, policy, 0)?;
    
    println!("✓ Filesystem policy configured:");
    println!("  Allowed write directory: {}", allowed_path);
    
    Ok(allowed_path)
}
