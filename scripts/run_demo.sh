#!/bin/bash

echo "🚀 IoT & Web Security Testing Framework"
echo "========================================"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Check prerequisites
check_prerequisites() {
    echo -e "${BLUE}Checking prerequisites...${NC}"
    
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}Docker not found. Please install Docker first.${NC}"
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        echo -e "${RED}Docker Compose not found. Please install Docker Compose first.${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✓ Prerequisites satisfied${NC}"
}

# Start Docker services
start_services() {
    echo -e "${BLUE}Starting Docker services...${NC}"
    docker-compose up -d
    
    echo "Waiting for services to be ready..."
    sleep 10
    
    echo -e "${GREEN}✓ Docker services started${NC}"
}

# Main function
main() {
    check_prerequisites
    start_services
    
    echo -e "\n${GREEN}✅ Framework is ready!${NC}"
    echo -e "${YELLOW}Access Points:${NC}"
    echo "  🌐 Web Interface: http://localhost"
    echo "  📊 Kibana (SIEM): http://localhost:5601"
    echo "  ⛓️  Ganache: http://localhost:7545"
    echo "  📈 Prometheus: http://localhost:9090"
    echo ""
    echo -e "Run '${YELLOW}docker-compose logs -f${NC}' to view logs"
    echo -e "Run '${YELLOW}docker-compose down${NC}' to stop all services"
}

main
