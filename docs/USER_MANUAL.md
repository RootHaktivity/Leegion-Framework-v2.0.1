# Leegion Framework v2.0 - User Manual

## Table of Contents
1. [Installation](#installation)
2. [Configuration](#configuration)
3. [Getting Started](#getting-started)
4. [Module Reference](#module-reference)
5. [Security Features](#security-features)
6. [Troubleshooting](#troubleshooting)
7. [Best Practices](#best-practices)
8. [Advanced Usage](#advanced-usage)

## Installation

### System Requirements
- **Operating System**: Linux (Ubuntu 20.04+, Kali Linux, Debian 11+)
- **Python**: 3.11 or higher
- **Memory**: Minimum 2GB RAM (4GB recommended)
- **Storage**: 500MB free space
- **Network**: Internet connection for updates and downloads

### Quick Installation
```bash
# Download and install
git clone https://github.com/Leegion/leegion-framework.git
cd leegion-framework
sudo python3 leegion_manager.py install

# Run the framework
leegion
```

### Alternative Installation Methods
```bash
# Using Makefile
make install

# Manual installation
python3 leegion_manager.py install --verbose
```

### Verification
```bash
# Check installation status
python3 leegion_manager.py status

# Run tests
python3 leegion_manager.py test

# Check version
leegion --version
```

## Configuration

### Initial Setup
The framework creates a default configuration on first run:
- **Location**: `~/.config/leegion/config.json`
- **Permissions**: 600 (user read/write only)

### Key Configuration Options

#### Basic Settings
```json
{
    "log_level": "INFO",
    "max_threads": 50,
    "timeout": 30,
    "colored_output": true,
    "auto_save_results": true
}
```

#### Module-Specific Settings
```json
{
    "vpn_config_dir": "./vpn_configs",
    "output_dir": "./reports/output",
    "wpscan_api_token": "enc:your_encrypted_token_here",
    "subdomain_wordlist": "./wordlists/subdomains.txt",
    "directory_wordlist": "./wordlists/dirb/common.txt"
}
```

### Security Configuration
- **API Token Encryption**: Automatically enabled
- **Rate Limiting**: 10 requests/second (configurable)
- **Input Validation**: Always enabled
- **Path Security**: System directory protection

### Updating Configuration
```bash
# Interactive configuration
python3 leegion_manager.py configure

# Direct edit
nano ~/.config/leegion/config.json

# Programmatic update
python3 -c "
from config.settings import update_config_value
update_config_value('max_threads', 100)
"
```

## Getting Started

### First Run
1. **Start the framework**: `leegion`
2. **Select a module**: Choose from the main menu
3. **Follow prompts**: Enter target information
4. **Review results**: Check output and reports

### Basic Workflow
```bash
# 1. Start VPN (recommended)
leegion
# Select: VPN Manager
# Choose: Connect VPN

# 2. Perform reconnaissance
# Select: Network Scanner
# Choose: Quick Scan
# Enter: Target IP

# 3. Analyze results
# Select: View Results
# Export: Choose format
```

### Command Line Interface
```bash
# Direct module access
leegion --module nmap --target 192.168.1.1
leegion --module ssl --target example.com
leegion --module wpscan --target https://example.com

# Batch operations
leegion --batch targets.txt --module subdomain
leegion --config custom_config.json
```

## Module Reference

### 1. VPN Manager
**Purpose**: Secure network connections for ethical hacking

#### Features
- OpenVPN integration
- Connection monitoring
- IP tracking
- Multiple display modes

#### Usage
```bash
# Connect to VPN
1. Select VPN Manager
2. Choose "Connect VPN"
3. Select configuration
4. Choose display mode

# Monitor connection
1. Select "Show Connection Status"
2. View real-time information
3. Check IP changes
```

#### Configuration Files
- **Location**: `./vpn_configs/`
- **Format**: `.ovpn` files
- **Import**: Use "Import VPN Config" option

### 2. Network Scanner (Nmap)
**Purpose**: Network reconnaissance and port scanning

#### Scan Types
- **Quick Scan**: Fast port discovery
- **Full TCP Scan**: Comprehensive port enumeration
- **Stealth Scan**: SYN scanning
- **Vulnerability Scan**: NSE script execution

#### Usage Examples
```bash
# Quick scan
Target: 192.168.1.1
Result: Common ports, basic service detection

# Full scan
Target: 192.168.1.0/24
Result: All ports, service versions, OS detection

# Custom scan
Arguments: -sS -sV -O --script vuln
Result: Stealth scan with vulnerability assessment
```

### 3. WordPress Scanner (WPScan)
**Purpose**: WordPress security assessment

#### Features
- User enumeration
- Plugin/theme detection
- Vulnerability scanning
- API integration

#### Setup
```bash
# Install WPScan
sudo apt-get install wpscan
# OR
gem install wpscan

# Configure API token
1. Get token from https://wpscan.com/api
2. Enter in configuration
3. Token is automatically encrypted
```

#### Scan Types
- **Basic Scan**: Theme/plugin enumeration
- **User Enumeration**: Discover usernames
- **Vulnerability Scan**: Check for known vulnerabilities
- **Aggressive Scan**: Comprehensive assessment

### 4. Subdomain Enumerator
**Purpose**: Discover subdomains of target domains

#### Techniques
- **DNS Bruteforce**: Wordlist-based enumeration
- **Certificate Transparency**: SSL certificate logs
- **Search Engine**: Passive enumeration
- **Permutation**: Pattern-based discovery

#### Usage
```bash
# Wordlist enumeration
Domain: example.com
Wordlist: Built-in common subdomains
Result: Discovered subdomains list

# Comprehensive scan
Domain: example.com
Techniques: All methods
Result: Complete subdomain inventory
```

### 5. Directory Bruteforcer
**Purpose**: Web directory and file discovery

#### Features
- Multiple wordlists
- Custom extensions
- Recursive scanning
- Rate limiting

#### Scan Types
- **Quick Scan**: Common directories
- **Comprehensive Scan**: Large wordlist
- **Custom Scan**: User-defined paths
- **Extension Scan**: File type discovery

#### Configuration
```json
{
    "max_threads": 20,
    "timeout": 10,
    "user_agent": "Leegion-Framework/2.0"
}
```

### 6. SSL/TLS Analyzer
**Purpose**: Certificate and encryption analysis

#### Analysis Types
- **Certificate Validation**: Expiry, issuer, subject
- **Cipher Suite Testing**: Encryption strength
- **Vulnerability Assessment**: Known SSL/TLS issues
- **Security Headers**: HTTP security configuration

#### Usage
```bash
# Single host analysis
Target: example.com:443
Result: Certificate details, cipher information

# Batch analysis
Targets: hosts.txt
Result: Comparative analysis report
```

### 7. Command Helper
**Purpose**: Cybersecurity tool cheatsheets and references

#### Features
- Tool-specific commands
- Vulnerability references
- Payload generators
- Custom command management

#### Categories
- **Network Tools**: Nmap, Netcat, etc.
- **Web Tools**: Burp Suite, OWASP ZAP
- **Exploitation**: Metasploit, SQLMap
- **Forensics**: Volatility, Autopsy

### 8. File Downloader
**Purpose**: Secure file downloads with rate limit bypass

#### Features
- Multiple download methods
- Rate limit handling
- Resume capability
- Progress tracking

#### Methods
- **curl**: Command-line downloader
- **requests**: Python HTTP library
- **wget**: Alternative downloader
- **urllib**: Built-in Python library

### 9. Reverse Shell Generator
**Purpose**: Multi-language reverse shell payloads

#### Languages Supported
- Bash, Python, PowerShell
- PHP, Perl, Ruby
- Java, Go, Lua, Node.js

#### Features
- **Payload Encoding**: Base64, URL encoding
- **Listener Setup**: Netcat, PowerShell
- **Custom Payloads**: User-defined templates
- **Favorites**: Save frequently used payloads

## Security Features

### Input Validation
All user inputs are validated for:
- **Type checking**: IP addresses, URLs, domains
- **Format validation**: Proper syntax and structure
- **Security patterns**: Injection attempt detection
- **Length limits**: Prevent buffer overflow attacks

### Rate Limiting
- **Network Operations**: 10 requests/second
- **Thread-Safe**: Works across concurrent operations
- **Configurable**: Adjustable per module
- **Automatic**: No user intervention required

### API Token Security
- **Encryption at Rest**: Tokens stored encrypted
- **Transparent Access**: Automatic decryption
- **Secure Storage**: Industry-standard encryption
- **Key Management**: Secure key generation and storage

### Path Security
- **Traversal Protection**: Prevent directory traversal
- **Symlink Protection**: Block symbolic link attacks
- **System Directory Blocking**: Prevent access to system files
- **Safe File Operations**: Secure filename generation

### Command Sanitization
- **Dangerous Command Filtering**: Remove harmful commands
- **Argument Validation**: Check command parameters
- **Length Limits**: Prevent command injection
- **Safe Execution**: Controlled subprocess execution

## Troubleshooting

### Common Issues

#### Installation Problems
```bash
# Permission denied
sudo python3 leegion_manager.py install

# Python version issues
python3 --version  # Should be 3.11+

# Missing dependencies
python3 leegion_manager.py install --force
```

#### Network Issues
```bash
# Rate limiting too aggressive
# Edit core/security.py
network_rate_limiter = InMemoryRateLimiter(max_calls=20, period=1.0)

# Connection timeouts
# Increase timeout in configuration
"timeout": 60

# Firewall blocking
# Check firewall settings
sudo ufw status
```

#### Module-Specific Issues

**VPN Manager**
```bash
# OpenVPN not found
sudo apt-get install openvpn

# Permission denied
sudo chmod +x /usr/bin/openvpn

# Configuration errors
# Check .ovpn file syntax
openvpn --config file.ovpn --show-certs
```

**Nmap Scanner**
```bash
# Nmap not found
sudo apt-get install nmap

# Permission denied (for certain scans)
sudo nmap -sS target

# Output parsing errors
# Check nmap version compatibility
nmap --version
```

**WPScan Integration**
```bash
# WPScan not found
sudo apt-get install wpscan
# OR
gem install wpscan

# API token issues
# Verify token at https://wpscan.com/api
# Re-enter token in configuration
```

**SSL Analyzer**
```bash
# Certificate errors
# Check target accessibility
# Verify port configuration
# Check firewall settings
```

### Performance Issues

#### Slow Scans
```bash
# Reduce thread count
"max_threads": 10

# Increase timeouts
"timeout": 60

# Use smaller wordlists
# Select "Quick Scan" options
```

#### Memory Usage
```bash
# Monitor memory
htop
# OR
ps aux | grep python

# Reduce concurrent operations
# Close unused modules
# Restart framework if needed
```

#### Network Bottlenecks
```bash
# Check bandwidth
speedtest-cli

# Adjust rate limits
# Modify network_rate_limiter settings

# Use local resources
# Download wordlists locally
```

### Error Messages

#### Security Validation Failed
```
[!] Security validation failed: Invalid IP address format
```
**Solution**: Check input format, ensure valid IP/URL/domain

#### Rate Limiting
```
[!] Rate limit exceeded, waiting...
```
**Solution**: Wait for rate limit to reset, or adjust settings

#### Permission Denied
```
[!] Permission denied: /path/to/file
```
**Solution**: Check file permissions, run with appropriate privileges

#### Network Error
```
[!] Network error: Connection timeout
```
**Solution**: Check network connectivity, increase timeout

## Best Practices

### Security
1. **Always Use VPN**: Enable VPN before reconnaissance
2. **Validate Targets**: Only scan authorized systems
3. **Monitor Logs**: Check framework logs regularly
4. **Update Regularly**: Keep framework updated
5. **Secure Configuration**: Protect sensitive data

### Performance
1. **Optimize Thread Count**: Match system capabilities
2. **Use Appropriate Timeouts**: Balance speed vs reliability
3. **Monitor Resources**: Watch CPU/memory usage
4. **Batch Operations**: Group related scans
5. **Cache Results**: Avoid redundant scans

### Workflow
1. **Plan Ahead**: Define scope and objectives
2. **Document Everything**: Keep detailed notes
3. **Validate Results**: Cross-check findings
4. **Export Reports**: Save results in multiple formats
5. **Clean Up**: Remove temporary files

### Legal Compliance
1. **Get Authorization**: Written permission required
2. **Follow Scope**: Stay within agreed boundaries
3. **Document Activities**: Keep audit trail
4. **Report Findings**: Share results appropriately
5. **Respect Privacy**: Handle data responsibly

## Advanced Usage

### Custom Modules
```python
# Create custom module
from core.base_module import BaseModule

class CustomModule(BaseModule):
    def __init__(self, config):
        super().__init__(config, "Custom_Module")
    
    def run(self):
        # Your module logic here
        pass
```

### Configuration Management
```python
# Programmatic configuration
from config.settings import load_config, save_config

config = load_config()
config['custom_setting'] = 'value'
save_config(config)
```

### Automation
```bash
# Script automation
#!/bin/bash
leegion --module nmap --target $1 --output nmap_results.xml
leegion --module ssl --target $1 --output ssl_results.json
leegion --module subdomain --target $1 --output subdomains.txt
```

### Integration
```python
# API integration
import requests

# Framework API calls
response = requests.post('http://localhost:8080/api/scan', {
    'target': 'example.com',
    'module': 'nmap',
    'options': {'scan_type': 'quick'}
})
```

### Reporting
```bash
# Generate comprehensive report
leegion --report all --format html --output report.html

# Custom report templates
# Edit templates in reports/templates/
# Use custom CSS for styling
```

---

## Support

### Getting Help
- **Documentation**: Check this manual first
- **GitHub Issues**: Report bugs and feature requests
- **Community**: Join our Discord/Telegram
- **Email**: contact@leegion.com

### Contributing
1. Fork the repository
2. Create feature branch
3. Make changes
4. Add tests
5. Submit pull request

### Version History
- **v2.0**: Major rewrite with security features
- **v1.5**: Enhanced modules and reporting
- **v1.0**: Initial release

---

*This manual covers Leegion Framework v2.0. For the latest updates, check the GitHub repository.* 