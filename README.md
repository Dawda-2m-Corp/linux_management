# Linux Management Scripts

A comprehensive collection of bash scripts for managing and maintaining Linux systems. This repository provides unified interfaces for common system administration tasks including monitoring, backups, user management, network configuration, and security hardening.

## Features

- **System Monitoring** - Real-time resource monitoring with configurable alerts
- **Package Management** - Unified interface for different package managers (apt, yum, dnf, pacman, zypper)
- **Service Management** - Manage systemd and SysV services
- **Backup Solutions** - Automated system backups with compression
- **Log Analysis** - Parse and analyze system logs for errors and patterns
- **User Management** - Comprehensive user, group, and permission management
- **Network Configuration** - Network interface and routing management
- **Security Hardening** - Basic security audit and hardening tools

## Repository Structure

```
linux_management/
├── linux_manager.sh     # Interactive master script
├── scripts/
│   ├── system/           # System monitoring and information
│   ├── packages/         # Package management utilities
│   ├── services/         # Service management tools
│   ├── backup/          # Backup and restore scripts
│   ├── logs/            # Log analysis tools
│   ├── users/           # User and permission management
│   ├── network/         # Network configuration utilities
│   └── security/        # Security and hardening scripts
├── config/              # Configuration files
├── examples/            # Usage examples and cron job templates
├── docs/               # Documentation
└── README.md           # This file
```

## Quick Start

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/asembereng/linux_management.git
   cd linux_management
   ```

2. Make scripts executable:
   ```bash
   chmod +x scripts/**/*.sh
   chmod +x linux_manager.sh
   ```

### Interactive Menu (Recommended for Beginners)

Launch the interactive menu system:
```bash
./linux_manager.sh
```

This provides a user-friendly interface to access all tools with guided prompts.

### Basic Usage Examples

#### System Information
```bash
# Get comprehensive system information
./scripts/system/system_info.sh

# Monitor system resources (CPU: 80%, Memory: 85%, Disk: 90%)
./scripts/system/system_monitor.sh 80 85 90
```

#### Package Management
```bash
# Update package lists
./scripts/packages/package_manager.sh update

# Install a package
./scripts/packages/package_manager.sh install nginx

# Search for packages
./scripts/packages/package_manager.sh search apache
```

#### Service Management
```bash
# Check service status
./scripts/services/service_manager.sh status nginx

# Restart a service
sudo ./scripts/services/service_manager.sh restart apache2

# List all services
./scripts/services/service_manager.sh list
```

#### Backup Operations
```bash
# Backup system directories with compression
sudo ./scripts/backup/backup_system.sh -s -c

# Backup specific directory
./scripts/backup/backup_system.sh /home/user
```

#### Log Analysis
```bash
# Show log summary
./scripts/logs/log_analyzer.sh -s

# Search for errors in today's logs
./scripts/logs/log_analyzer.sh -e -d $(date +%Y-%m-%d)

# Follow logs in real-time
./scripts/logs/log_analyzer.sh -f /var/log/syslog
```

#### User Management
```bash
# Add new user
sudo ./scripts/users/user_manager.sh add-user newuser

# Add user to group
sudo ./scripts/users/user_manager.sh add-to-group newuser sudo

# List all users
./scripts/users/user_manager.sh list-users
```

#### Network Configuration
```bash
# Show network status
./scripts/network/network_config.sh status

# List network interfaces
./scripts/network/network_config.sh interfaces

# Set static IP (requires root)
sudo ./scripts/network/network_config.sh set-ip eth0 192.168.1.100 255.255.255.0
```

#### Security Hardening
```bash
# Perform security audit
./scripts/security/security_hardening.sh audit

# Apply basic hardening (requires root)
sudo ./scripts/security/security_hardening.sh harden

# Harden SSH configuration (requires root)
sudo ./scripts/security/security_hardening.sh ssh-harden
```

## Script Details

### System Scripts

| Script | Description | Root Required |
|--------|-------------|---------------|
| `system_info.sh` | Display comprehensive system information | No |
| `system_monitor.sh` | Monitor resources with configurable thresholds | No |

### Package Management

| Script | Description | Root Required |
|--------|-------------|---------------|
| `package_manager.sh` | Unified package manager interface | Yes (for install/remove) |

**Supported Package Managers:**
- APT (Debian/Ubuntu)
- YUM (RHEL/CentOS)
- DNF (Fedora)
- Pacman (Arch Linux)
- Zypper (openSUSE)

### Service Management

| Script | Description | Root Required |
|--------|-------------|---------------|
| `service_manager.sh` | Manage systemd and SysV services | Yes (for control operations) |

### Backup Tools

| Script | Description | Root Required |
|--------|-------------|---------------|
| `backup_system.sh` | Create compressed backups of directories | Yes (for system directories) |

### Log Analysis

| Script | Description | Root Required |
|--------|-------------|---------------|
| `log_analyzer.sh` | Analyze system logs for patterns and errors | No |

### User Management

| Script | Description | Root Required |
|--------|-------------|---------------|
| `user_manager.sh` | Comprehensive user and group management | Yes |

### Network Tools

| Script | Description | Root Required |
|--------|-------------|---------------|
| `network_config.sh` | Network interface and routing management | Yes (for configuration) |

### Security Tools

| Script | Description | Root Required |
|--------|-------------|---------------|
| `security_hardening.sh` | Security audit and basic hardening | Yes (for hardening) |

## ⚙️ Configuration

Configuration files are located in the `config/` directory:

- `system_monitor.conf` - Monitoring thresholds and settings
- `backup.conf` - Backup destinations and retention policies

## Automation

The `examples/` directory contains:

- `cron_examples.sh` - Example cron job configurations
- `usage_examples.sh` - Comprehensive usage examples

### Example Cron Jobs

```bash
# System monitoring every 5 minutes
*/5 * * * * /path/to/linux_management/scripts/system/system_monitor.sh

# Daily backup at 2 AM
0 2 * * * /path/to/linux_management/scripts/backup/backup_system.sh -s -c

# Weekly log analysis
0 3 * * 0 /path/to/linux_management/scripts/logs/log_analyzer.sh -s
```

## Security Considerations

- **Always test scripts in a non-production environment first**
- **Review script contents before running with root privileges**
- **Backup important configurations before making changes**
- **Monitor logs in `/var/log/` for operation details**
- **Use the security hardening script to improve system security**

## Logging

Most scripts log their activities to `/var/log/`:
- System monitor: `/var/log/system_monitor.log`
- Backup operations: `/var/log/backup.log`
- Security operations: `/var/log/security_hardening.log`

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add your scripts following the existing structure
4. Test thoroughly
5. Submit a pull request

## License

This project is open source. Please ensure you understand and comply with your organization's policies before using these scripts in production environments.

## ⚠️ Disclaimer

These scripts are provided as-is. Always test in a non-production environment and ensure you have proper backups before running any system administration scripts. The authors are not responsible for any damage or data loss that may occur from using these scripts.

## Support

For issues, questions, or contributions, please use the GitHub issue tracker.

---

**Happy Linux Administration!**
