# 🛡️ SecurityWatch Pro

**Professional security monitoring with intelligent pattern recognition, automated threat detection, and comprehensive reporting for Windows, Linux, and macOS systems.**

[![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](https://github.com/ahmganbit/SecuriWatch)

## 🚀 Features

### 🔍 **Advanced Threat Detection**
- **Real-time log monitoring** with intelligent pattern recognition
- **Brute force attack detection** with configurable thresholds
- **SQL injection and web attack detection**
- **Privilege escalation attempt monitoring**
- **Network scanning and port scan detection**
- **Custom threat pattern support**

### 📊 **Comprehensive Analysis**
- **Threat scoring system** (0-100 scale)
- **IP reputation tracking** with automatic blocking recommendations
- **Timeline analysis** with peak activity detection
- **Geolocation analysis** for attack sources
- **Correlation engine** for related security events

### 🚨 **Intelligent Alerting**
- **Real-time email alerts** with HTML formatting
- **Configurable severity thresholds**
- **Rate limiting** to prevent alert spam
- **Console and log-based notifications**
- **Test alert functionality**

### 📈 **Professional Reporting**
- **Beautiful HTML reports** with charts and graphs
- **JSON API** for integration with other tools
- **Executive summary** with key metrics
- **Actionable security recommendations**
- **Historical trend analysis**

### 🔧 **Enterprise Features**
- **Multi-platform support** (Windows, Linux, macOS)
- **Automatic log file detection**
- **Encrypted configuration storage**
- **Database retention policies**
- **Command-line interface**
- **Daemon mode** for continuous monitoring

## 📦 Installation

### Quick Install
```bash
# Clone the repository
git clone https://github.com/ahmganbit/SecuriWatch.git
cd SecuriWatch

# Install dependencies
pip install -r requirements.txt

# Install SecurityWatch Pro
pip install -e .
```

### System Requirements
- **Python 3.7+**
- **SQLite3** (included with Python)
- **Read access** to system log files
- **SMTP server** (for email alerts)

## 🚀 Quick Start

### 1. **Start Monitoring**
```bash
# Start in interactive mode
securitywatch start

# Start in daemon mode (background)
securitywatch start --daemon
```

### 2. **Check Status**
```bash
securitywatch status
```

### 3. **Run Manual Scan**
```bash
securitywatch scan
```

### 4. **Generate Report**
```bash
# Generate HTML report for last 24 hours
securitywatch report --hours 24

# Generate JSON report
securitywatch report --type json --hours 48
```

### 5. **Analyze Specific IP**
```bash
securitywatch analyze-ip 192.168.1.100
```

## 📋 Configuration

### **Automatic Configuration**
SecurityWatch Pro automatically detects and monitors common log files:

**Linux:**
- `/var/log/auth.log` (Ubuntu/Debian)
- `/var/log/secure` (CentOS/RHEL)
- `/var/log/syslog`
- `/var/log/apache2/access.log`
- `/var/log/nginx/access.log`

**macOS:**
- `/var/log/system.log`
- `/var/log/auth.log`

**Windows:**
- `C:\Windows\System32\winevt\Logs\Security.evtx`
- `C:\Windows\System32\winevt\Logs\System.evtx`

### **Email Alerts Setup**
```python
from securitywatch import SecurityWatchConfig

config = SecurityWatchConfig()
config.update_email_config(
    smtp_server="smtp.gmail.com",
    smtp_port=587,
    username="your-email@gmail.com",
    password="your-app-password",
    from_email="security@yourcompany.com",
    to_emails=["admin@yourcompany.com", "security-team@yourcompany.com"]
)
```

### **Add Custom Log Files**
```bash
securitywatch add-log /path/to/custom.log
```

## 🔍 Threat Detection Patterns

SecurityWatch Pro includes built-in detection for:

| **Attack Type** | **Severity** | **Description** |
|-----------------|--------------|-----------------|
| SSH Failed Login | Medium | Failed SSH authentication attempts |
| SSH Invalid User | High | Login attempts with invalid usernames |
| Windows Failed Login | Medium | Windows logon failures |
| SQL Injection | Critical | Potential SQL injection attacks |
| Command Injection | Critical | Command injection attempts |
| Directory Traversal | High | Directory traversal attacks |
| Privilege Escalation | High | Sudo/admin privilege escalation attempts |
| Port Scanning | Medium | Network scanning activity |
| Brute Force | High/Critical | Multiple failed login attempts |

## 📊 Example Output

### **Console Status**
```
🛡️ SecurityWatch Pro Status
========================================
Status: 🟢 Running
Log Files: 5
Total Events: 1,247

Events by Severity:
  CRITICAL: 3
  HIGH: 15
  MEDIUM: 89
  LOW: 1,140

Top Attacking IPs:
  192.168.1.100: 45 events
  10.0.0.50: 23 events
```

### **Threat Analysis**
```
🔍 Analyzing IP address: 192.168.1.100
📊 Total Events: 45
🎯 Threat Level: HIGH
⏰ First Seen: 2025-01-15 14:30:22
⏰ Last Seen: 2025-01-15 16:45:18
👤 Usernames Targeted: admin, root, user, test, guest
🚨 WARNING: This IP shows brute force attack patterns!
```

## 🧪 Testing

Run the comprehensive test suite:

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest tests/ --cov=securitywatch --cov-report=html

# Run specific test file
pytest tests/test_core.py -v
```

## 📚 API Usage

### **Python API**
```python
from securitywatch import SecurityWatchMonitor, SecurityWatchConfig

# Initialize
config = SecurityWatchConfig()
monitor = SecurityWatchMonitor(config)

# Start monitoring
monitor.start_monitoring()

# Get recent events
events = monitor.get_recent_events(hours=24)

# Analyze specific IP
analysis = monitor.analyze_ip("192.168.1.100")

# Generate report
from securitywatch.core.reports import ReportGenerator
report_gen = ReportGenerator(monitor.database)
html_report = report_gen.generate_html_report(hours=24)
```

### **Command Line Interface**
```bash
# Show recent events
securitywatch events --hours 1 --limit 20

# List monitored log files
securitywatch logs

# Stop monitoring
securitywatch stop
```

## 🔧 Advanced Configuration

### **Custom Threat Patterns**
```python
from securitywatch.models.events import ThreatPattern
from securitywatch.core.patterns import LogPatternMatcher

# Create custom pattern
custom_pattern = ThreatPattern(
    name="Custom Application Attack",
    description="Detect attacks on custom application",
    regex_pattern=r"ATTACK_DETECTED from (?P<ip>\d+\.\d+\.\d+\.\d+)",
    severity="high",
    threshold_count=3,
    time_window=300
)

# Add to pattern matcher
matcher = LogPatternMatcher()
matcher.add_custom_pattern(custom_pattern)
```

## 🛡️ Security Considerations

1. **File Permissions**: Ensure SecurityWatch Pro has read access to log files
2. **Database Security**: Store database in secure location with appropriate permissions
3. **Email Credentials**: Use app-specific passwords for email authentication
4. **Network Security**: Monitor SecurityWatch Pro's network connections
5. **Regular Updates**: Keep SecurityWatch Pro and dependencies updated

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: [Wiki](https://github.com/ahmganbit/SecuriWatch/wiki)
- **Issues**: [GitHub Issues](https://github.com/ahmganbit/SecuriWatch/issues)
- **Email**: support@sysadmintoolspro.com

---

**⚠️ Disclaimer**: SecurityWatch Pro is a monitoring tool. It does not replace proper security practices, firewalls, or professional security audits. Always follow security best practices and consult with security professionals for critical systems.
