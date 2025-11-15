// Network Policy Implementations (NET-xxx)
// This module contains all network-related policy enforcement functions

use aya::{Btf, programs::Lsm, maps::Array};
use cmd_sandbox_common::policy_shared::NetworkPolicy;
use crate::policy::PolicyConfig;

// ----------------------------------------------------------------------------
// Network Policies (NET-xxx)
// ----------------------------------------------------------------------------

/// NET-001: Allow HTTP/HTTPS connections only to whitelisted domains
/// Enforcement: Block connections to non-whitelisted domains via eBPF
pub fn implement_net_001(ebpf: &mut aya::Ebpf, btf: &Btf, config: &PolicyConfig) -> anyhow::Result<()> {
    // Attach socket_connect LSM hook for domain filtering
    let program: &mut Lsm = ebpf.program_mut("socket_connect").unwrap().try_into()?;
    program.load("socket_connect", btf)?;
    program.attach()?;
    println!("✓ NET-001: Domain whitelist enforcement enabled");
    
    // Populate network policy map and whitelist IPs
    populate_network_policy(ebpf, config)?;
    Ok(())
}

/// NET-005: Block connections to private IP ranges
/// Enforcement: eBPF hook checks IP address against private ranges
pub fn implement_net_005(_ebpf: &mut aya::Ebpf, _btf: &Btf, config: &PolicyConfig) -> anyhow::Result<()> {
    if config.network_policies.block_private_ips {
        println!("✓ NET-005: Private IP blocking enabled (10.x, 172.16.x, 192.168.x, 127.x)");
        println!("  Enforced in socket_connect eBPF hook");
    }
    Ok(())
}

/// NET-006: Allow only ports 80 (HTTP) and 443 (HTTPS)
/// Enforcement: eBPF hook validates destination port
pub fn implement_net_006(_ebpf: &mut aya::Ebpf, _btf: &Btf, config: &PolicyConfig) -> anyhow::Result<()> {
    println!("✓ NET-006: Port restrictions enabled (allowed: {:?})", config.network_policies.allowed_ports);
    println!("  Enforced in socket_connect eBPF hook");
    Ok(())
}

// ----------------------------------------------------------------------------
// Helper Functions
// ----------------------------------------------------------------------------

pub fn populate_network_policy(ebpf: &mut aya::Ebpf, config: &PolicyConfig) -> anyhow::Result<()> {
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

pub fn populate_whitelisted_ips(ebpf: &mut aya::Ebpf, config: &PolicyConfig) -> anyhow::Result<()> {
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
