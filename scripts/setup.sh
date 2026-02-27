#!/bin/bash

echo "🚀 Setting up IoT & Web Security Testing Framework..."

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Create necessary directories
mkdir -p logs reports/generated data

# Set up environment file if not exists
if [ ! -f .env ]; then
    cat > .env << EOL
# Database Configuration
MONGO_URI=mongodb://localhost:27017/
MONGO_DB=security_framework

# Blockchain Configuration
GANACHE_URL=http://localhost:7545
CONTRACT_ADDRESS=

# SIEM Configuration
ELASTICSEARCH_HOST=localhost
ELASTICSEARCH_PORT=9200

# Security
SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
JWT_SECRET=$(python -c "import secrets; print(secrets.token_hex(32))")

# IoT
MQTT_BROKER=localhost
MQTT_PORT=1883

# App Configuration
DEBUG=True
TEST_MODE=True
MAX_PAYLOAD_SIZE=1024
REQUEST_TIMEOUT=30
EOL
    echo "✅ .env file created"
fi

echo "✅ Setup complete! Run 'source venv/bin/activate' to start"
