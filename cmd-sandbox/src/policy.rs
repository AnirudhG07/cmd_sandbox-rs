use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PolicyConfig {
    pub policy_version: String,
    pub command: String,
    pub network_policies: NetworkPolicies,
    pub filesystem_policies: FilesystemPolicies,
    pub memory_policies: MemoryPolicies,
    pub security_policies: SecurityPolicies,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetworkPolicies {
    pub allowed_domains: Vec<String>,
    pub allowed_ports: Vec<u16>,
    pub max_connections: u32,
    pub connection_timeout: u32,
    pub block_private_ips: bool,
    pub blocked_protocols: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FilesystemPolicies {
    pub allowed_write_dirs: Vec<String>,
    pub allowed_read_dirs: Vec<String>,
    pub max_file_size: u64,
    pub max_total_storage: u64,
    pub blocked_paths: Vec<String>,
    pub prevent_execution: bool,
    #[serde(default)]
    pub enable_permission_watcher: bool,
    #[serde(default = "default_watcher_permissions")]
    pub watcher_permissions: String,
}

fn default_watcher_permissions() -> String {
    "600".to_string()  // Read/write for owner only
}

impl FilesystemPolicies {
    /// Parse the watcher_permissions string (e.g., "600") to u32 mode
    pub fn get_watcher_mode(&self) -> u32 {
        u32::from_str_radix(&self.watcher_permissions, 8).unwrap_or(0o600)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MemoryPolicies {
    pub max_memory: u64,
    pub max_stack_size: u64,
    pub max_cpu_time: u32,
    pub cpu_limit_percent: u32,
    pub block_fork_exec: bool,
    pub block_executable_mmap: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SecurityPolicies {
    pub run_as_user: String,
    pub blocked_environment: Vec<String>,
    pub allowed_signals: Vec<String>,
    pub isolate_network: bool,
    pub block_kernel_memory: bool,
    pub block_network_admin: bool,
}

impl PolicyConfig {
    /// Load policy configuration from a JSON file
    pub fn from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let contents = fs::read_to_string(path)?;
        let config: PolicyConfig = serde_json::from_str(&contents)?;
        Ok(config)
    }

    /// Load default policy configuration from bundled file
    pub fn default() -> anyhow::Result<Self> {
        // Try to load from current directory, then from config directory
        let paths = vec![
            "policy_config.json",
            "../policy_config.json",
            "/etc/cmd-sandbox/policy_config.json",
        ];

        for path in paths {
            if Path::new(path).exists() {
                return Self::from_file(path);
            }
        }

        // If no file found, return hardcoded defaults
        Ok(Self::hardcoded_default())
    }

    /// Hardcoded default configuration (fallback)
    fn hardcoded_default() -> Self {
        PolicyConfig {
            policy_version: "1.0".to_string(),
            command: "curl".to_string(),
            network_policies: NetworkPolicies {
                allowed_domains: vec![
                    "example.com".to_string(),
                    "iisc.ac.in".to_string(),
                ],
                allowed_ports: vec![80, 443],
                max_connections: 3,
                connection_timeout: 30,
                block_private_ips: true,
                blocked_protocols: vec!["ftp".to_string(), "sftp".to_string()],
            },
            filesystem_policies: FilesystemPolicies {
                allowed_write_dirs: vec!["/tmp/curl_downloads/".to_string()],
                allowed_read_dirs: vec!["~".to_string()],
                max_file_size: 10 * 1024 * 1024, // 10MB
                max_total_storage: 50 * 1024 * 1024, // 50MB
                blocked_paths: vec![
                    "/etc/".to_string(),
                    "/bin/".to_string(),
                    "/sbin/".to_string(),
                    "/usr/".to_string(),
                ],
                prevent_execution: true,
                enable_permission_watcher: false,
                watcher_permissions: "600".to_string(),
            },
            memory_policies: MemoryPolicies {
                max_memory: 100 * 1024 * 1024, // 100MB
                max_stack_size: 8 * 1024 * 1024, // 8MB
                max_cpu_time: 120, // 2 minutes
                cpu_limit_percent: 50,
                block_fork_exec: true,
                block_executable_mmap: true,
            },
            security_policies: SecurityPolicies {
                run_as_user: "nobody".to_string(),
                blocked_environment: vec![
                    "PASSWORD".to_string(),
                    "KEY".to_string(),
                    "SECRET".to_string(),
                ],
                allowed_signals: vec!["TERM".to_string(), "INT".to_string()],
                isolate_network: true,
                block_kernel_memory: true,
                block_network_admin: true,
            },
        }
    }

    /// Validate the policy configuration
    pub fn validate(&self) -> anyhow::Result<()> {
        // Validate version
        if self.policy_version != "1.0" {
            anyhow::bail!("Unsupported policy version: {}", self.policy_version);
        }

        // Validate command
        if self.command != "curl" && self.command != "wget" {
            anyhow::bail!("Unsupported command: {}", self.command);
        }

        // Validate ports
        for port in &self.network_policies.allowed_ports {
            if *port == 0 {
                anyhow::bail!("Port 0 is not valid");
            }
        }

        // Validate memory limits
        if self.memory_policies.max_memory == 0 {
            anyhow::bail!("Memory limit cannot be 0");
        }

        if self.memory_policies.cpu_limit_percent > 100 {
            anyhow::bail!("CPU limit percent cannot exceed 100");
        }

        Ok(())
    }

    /// Get formatted CPU limit for cgroup
    pub fn get_cpu_limit_string(&self) -> String {
        let period = 1_000_000; // 1 second in microseconds
        let quota = (period * self.memory_policies.cpu_limit_percent as u64) / 100;
        format!("{} {}", quota, period)
    }
}
