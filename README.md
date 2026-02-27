# IoT & Web Security Testing Framework

## 🎯 Overview

A comprehensive security testing framework for IoT and web applications with blockchain-based audit trail and SIEM integration. Designed for educational purposes to demonstrate security concepts and defensive techniques covering 6 major subjects.

## ✨ Key Features

### 1. **Blockchain & Cryptography**
- Smart contract-based audit trail (Solidity)
- SHA-256 hashing for evidence
- Ganache blockchain integration
- Tamper-proof test record storage

### 2. **SIEM & Security Monitoring**
- ELK Stack integration (Elasticsearch, Kibana)
- Real-time log collection and analysis
- CEF (Common Event Format) logging
- Alert generation and management

### 3. **Cyber Threat Management**
- MITRE ATT&CK framework mapping
- Risk scoring and severity classification
- Threat intelligence integration
- Comprehensive threat analysis

### 4. **Authentication & IAM**
- Credential stuffing detection
- JWT vulnerability testing
- RBAC (Role-Based Access Control) analysis
- Session management testing

### 5. **Security Compliance**
- NIST Framework alignment
- ISO 27001 compliance mapping
- Gap analysis reporting
- Automated compliance checks

### 6. **IoT Security**
- MQTT protocol testing
- Device spoofing detection
- CoAP security analysis
- IoT device vulnerability scanning

## 🏗️ Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Web Interface │────▶│   Core Engine   │────▶│    Modules      │
│   (HTML/CSS/JS) │     │   (Python)      │     │ Web/IAM/IoT/... │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                               │
                ┌──────────────┼──────────────┐
                ▼              ▼              ▼
        ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
        │  Blockchain │ │    SIEM     │ │   Reports   │
        │  (Ganache)  │ │  (ELK)      │ │   (PDF)     │
        └─────────────┘ └─────────────┘ └─────────────┘
```

## 📂 Project Structure

```
iot-web-security-framework/
├── backend/                    # Python Flask backend
│   ├── core/                  # Core engine, safety, modules
│   ├── modules/               # Security testing modules
│   │   ├── web_security/      # SQL injection, XSS, Auth bypass
│   │   ├── iam_security/      # Credential, JWT, RBAC testing
│   │   ├── iot_security/      # MQTT, Device spoofing, CoAP
│   │   └── compliance/        # NIST, ISO mapping, reports
│   ├── blockchain/            # Smart contract integration
│   ├── siem/                  # ELK integration, log generation
│   └── app.py                 # Flask application
├── frontend/                  # Web interface
│   ├── index.html             # Main page
│   ├── css/style.css          # Styling
│   └── js/app.js              # Frontend logic
├── contracts/                 # Smart contracts
│   └── AttackAudit.sol        # Audit chain contract
├── tests/                     # Test suite
├── docker-compose.yml         # Docker orchestration
├── Dockerfile.backend         # Backend container
├── Dockerfile.frontend        # Frontend container
├── requirements.txt           # Python dependencies
├── nginx/conf/                # Nginx configuration
└── scripts/                   # Setup and deployment scripts
```

## 🚀 Quick Start

### Prerequisites

- Docker & Docker Compose
- Python 3.9+ (for local development)
- Node.js 14+ (optional, for frontend dev)
- 4GB+ RAM
- macOS/Linux/Windows with WSL2

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/iot-web-security-framework.git
cd iot-web-security-framework
```

2. **Run setup script**
```bash
chmod +x scripts/setup.sh
./scripts/setup.sh
```

3. **Start Docker services**
```bash
chmod +x scripts/run_demo.sh
./scripts/run_demo.sh
```

4. **Access the framework**
- Web Interface: http://localhost
- Kibana (SIEM): http://localhost:5601
- Ganache (Blockchain): http://localhost:7545
- Prometheus: http://localhost:9090

## 📖 Usage Guide

### Running Security Tests

1. **Select a module** from the dashboard (Web, IAM, or IoT)
2. **Configure target** (use safe test targets like localhost:8080)
3. **Click "Run Test"** to start the security test
4. **Monitor progress** in real-time
5. **View results** including vulnerabilities found
6. **Check blockchain verification** of test evidence
7. **Review SIEM logs** in Kibana dashboard

### Testing Safe Targets

The framework is configured to only test safe targets:
- `localhost` and `127.0.0.1`
- Test domains: `test.com`, `example.com`, `demo.app`
- Private networks: `192.168.x.x`, `10.x.x.x`

Attempting to test external/production systems will be blocked.

### Example: Running SQL Injection Test

```bash
# Navigate to Web Security module
# Click "SQL Injection Testing" button
# Verify target is set to: http://localhost:8080
# Click "Run Test"
# Wait for completion
# View results and blockchain hash
```

## 🔒 Safety Features

✅ **Target Validation** - Only allows safe/local targets
✅ **Payload Sanitization** - Removes destructive commands
✅ **Rate Limiting** - Prevents overwhelming targets
✅ **Read-Only Mode** - No data modification
✅ **Academic Focus** - Educational purposes only

## 🧪 Testing

Run unit tests:
```bash
python -m pytest tests/test_system.py -v
```

Check blockchain connection:
```bash
python -c "from backend.blockchain.blockchain_auditor import BlockchainAuditor; print(BlockchainAuditor().get_statistics())"
```

Test SIEM logging:
```bash
python -c "from backend.siem.log_generator import LogGenerator; print(LogGenerator().get_log_statistics())"
```

## 📊 API Endpoints

### Testing
- `POST /api/tests/run` - Run a security test
- `GET /api/tests/status/{test_id}` - Get test status
- `GET /api/tests/{test_id}` - Get test results
- `GET /api/tests` - List all tests

### Dashboard
- `GET /api/dashboard/stats` - Get dashboard statistics
- `GET /api/tests/recent` - Get recent tests

### Modules
- `GET /api/modules` - List available modules
- `GET /api/modules/{module_name}` - Get module info

### SIEM
- `GET /api/siem/alerts` - Get security alerts
- `GET /api/siem/logs` - Get SIEM logs

### Blockchain
- `GET /api/blockchain/status` - Get blockchain status
- `GET /api/blockchain/records` - Get blockchain records
- `GET /api/blockchain/verify/{hash}` - Verify evidence hash

### Reports
- `POST /api/reports/generate/{type}` - Generate report

## 🎓 Mapping to 6 Required Subjects

### 1. Blockchain & Cryptography (T1)
- Smart contract implementation (Solidity)
- SHA-256 hashing for evidence
- Ethereum/Ganache integration
- Tamper-proof record storage

### 2. SIEM & SOAR Integration (T2)
- Elasticsearch cluster setup
- Kibana dashboard creation
- Log analysis and correlation
- Automated response playbooks

### 3. Cyber Threat Management (T3)
- MITRE ATT&CK mapping
- Risk assessment framework
- Threat intelligence gathering
- Incident response procedures

### 4. Authentication & IAM (T4)
- Credential testing modules
- JWT vulnerability analysis
- RBAC permission testing
- Multi-factor authentication support

### 5. Security Compliance (T5)
- NIST Cybersecurity Framework
- ISO/IEC 27001 controls mapping
- Compliance gap analysis
- Audit trail reporting

### 6. IoT Security (T6)
- MQTT protocol testing
- Device authentication
- CoAP vulnerability scanning
- Firmware analysis tools

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `pytest tests/`
5. Commit and push
6. Submit a pull request

## 📝 License

MIT License - See LICENSE file

## ⚠️ Important Disclaimer

**FOR EDUCATIONAL PURPOSES ONLY**

This tool is designed for:
- Security education and training
- Testing in controlled/authorized environments only
- Academic research and demonstration

**Do NOT use against systems without explicit written permission.**

Unauthorized access to computer systems is illegal in most jurisdictions.

## 📚 References

- [MITRE ATT&CK Framework](https://mitre-attack.github.io/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [ISO/IEC 27001:2022](https://www.iso.org/isoiec-27001-information-security-management.html)
- [Ethereum Smart Contracts](https://ethereum.org/)
- [ELK Stack Documentation](https://www.elastic.co/guide/index.html)

## 🙏 Acknowledgments

- MITRE ATT&CK Team
- OWASP Community
- NIST Cybersecurity Team
- Ethereum Foundation
- Elastic Community

## 📧 Support

For questions or issues:
- GitHub Issues: [Link to issues]
- Email: your.email@university.edu
- Documentation: See `/docs` folder

---

**Last Updated:** February 2026
**Version:** 1.0.0
**Status:** Production Ready ✅
