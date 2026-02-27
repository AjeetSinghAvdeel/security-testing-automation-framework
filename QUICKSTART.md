# Quick Start Guide

## 🚀 Get Started in 5 Minutes

### Step 1: Navigate to Project Directory
```bash
cd /Volumes/Ajeet\ SSD/Projects/PBL/iot-web-security-framework
```

### Step 2: Make Scripts Executable
```bash
chmod +x scripts/setup.sh
chmod +x scripts/run_demo.sh
```

### Step 3: Run Startup Script
```bash
./scripts/run_demo.sh
```

This will:
- Check prerequisites
- Start all Docker containers
- Initialize the framework
- Display access points

### Step 4: Wait for Services (30-60 seconds)
Services starting:
- ✅ MongoDB (Database)
- ✅ Elasticsearch (SIEM)
- ✅ Kibana (Dashboards)
- ✅ Redis (Caching)
- ✅ MQTT (IoT)
- ✅ Ganache (Blockchain)
- ✅ Backend (Flask API)
- ✅ Frontend (Nginx)
- ✅ Prometheus (Monitoring)

### Step 5: Access the Application
Open in browser:
- **Web UI**: http://localhost
- **SIEM (Kibana)**: http://localhost:5601
- **Blockchain (Ganache)**: http://localhost:7545
- **Monitoring (Prometheus)**: http://localhost:9090

## 🧪 Running Your First Test

1. **Select a Module**
   - Click on "Web Security" card
   - Choose "SQL Injection Testing"

2. **Configure Target**
   - Target URL: `http://localhost:8080` (default)
   - Intensity: Medium (default)
   - Enable Blockchain: ✅
   - Enable SIEM: ✅

3. **Run Test**
   - Click "Run Test" button
   - Wait for completion (30-60 seconds)
   - View results in real-time

4. **Review Results**
   - Dashboard updates automatically
   - Check SIEM logs in Kibana
   - Verify blockchain hash

## 🔧 Local Development Setup

### Using Python Virtual Environment (Alternative to Docker)

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run Flask app
python -m flask run --host=0.0.0.0 --port=5000
```

### Frontend Development

```bash
# Install Node dependencies (if using npm)
cd frontend
npm install

# Serve with live reload
python -m http.server 8000
```

## 📊 Understanding the Project Structure

```
Project Root/
├── backend/          - Flask API & core logic
├── frontend/         - Web interface (HTML/CSS/JS)
├── contracts/        - Smart contracts (Solidity)
├── scripts/          - Setup & deployment
├── docker-compose.yml  - Container orchestration
└── README.md         - Full documentation
```

## 🎯 Mapping to 6 Subjects

| Subject | Implementation | Key Files |
|---------|----------------|-----------|
| **1. Blockchain** | Smart contract, SHA-256 hashing | `contracts/AttackAudit.sol`, `backend/blockchain/` |
| **2. SIEM/SOAR** | ELK integration, log collection | `backend/siem/`, `elasticsearch`, `kibana` |
| **3. Threat Mgmt** | MITRE mapping, risk scoring | `backend/core/result_processor.py`, MITRE constants |
| **4. IAM** | Credential, JWT, RBAC testing | `backend/modules/iam_security/` |
| **5. Compliance** | NIST, ISO reports | `backend/modules/compliance/` |
| **6. IoT** | MQTT, device testing | `backend/modules/iot_security/` |

## 🔍 Troubleshooting

### Services Not Starting
```bash
# Check Docker status
docker ps -a

# View logs
docker-compose logs -f

# Restart services
docker-compose restart
```

### Port Already in Use
```bash
# Kill process using port
# macOS/Linux:
lsof -ti:5000 | xargs kill -9

# Windows (PowerShell):
Get-Process | Where-Object {$_.Id -eq (Get-NetTCPConnection -LocalPort 5000).OwningProcess} | Stop-Process
```

### Backend Connection Issues
```bash
# Test Flask app
curl http://localhost:5000/api/health

# Test Elasticsearch
curl http://localhost:9200

# Test Blockchain
curl http://localhost:7545
```

## 📚 Next Steps

1. **Explore the Dashboard**
   - Review real-time statistics
   - Check recent test results
   - Monitor security alerts

2. **Run Security Tests**
   - Start with Web Security module
   - Try different test types
   - Review Kibana dashboards

3. **Review Smart Contracts**
   - Check `contracts/AttackAudit.sol`
   - Understand evidence hashing
   - See Ganache transactions

4. **Generate Reports**
   - Create pentest report
   - Generate compliance report
   - Export blockchain audit trail

5. **Study the Code**
   - Review safety checker
   - Understand test framework
   - Learn about SIEM integration

## 🛠️ Common Commands

```bash
# View all running containers
docker-compose ps

# View logs for specific service
docker-compose logs backend
docker-compose logs elasticsearch
docker-compose logs ganache

# Stop all services
docker-compose down

# Remove all containers and data
docker-compose down -v

# Rebuild containers
docker-compose build --no-cache

# Scale a service
docker-compose up -d --scale backend=2
```

## ⚠️ Safety Reminders

✅ **Only test local/safe targets**
- localhost, 127.0.0.1
- test.com, example.com
- Private networks

❌ **Do NOT test**
- Production systems
- External websites
- Systems without permission

## 📞 Getting Help

- Check `/docs` folder for detailed documentation
- Review comments in code files
- Check `README.md` for full API reference
- See logs: `docker-compose logs`

## 🎓 What You're Learning

This framework demonstrates:
- **Blockchain**: Smart contracts, cryptographic hashing, audit trails
- **SIEM**: Log aggregation, analysis, alerting, dashboarding
- **Cybersecurity**: Testing methodologies, vulnerability detection
- **Cloud/Docker**: Containerization, orchestration, microservices
- **Full Stack**: Backend (Python), Frontend (HTML/JS), Database, APIs

---

**Happy Learning! 🚀**

For questions or issues, check the main README.md or contact your instructor.
