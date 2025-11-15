#!/bin/bash

################################################################################
# SIEM Detection Engineering Lab - Automated Setup Script
# Version: 1.0.0
# Description: Automated deployment of Splunk + Elastic Stack lab environment
################################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"
MIN_DOCKER_VERSION="20.10"
MIN_MEMORY_GB=16

################################################################################
# Helper Functions
################################################################################

print_header() {
  echo -e "${BLUE}"
  echo "╔════════════════════════════════════════════════════════════════╗"
  echo "║  SIEM Detection Engineering Lab - Automated Setup              ║"
  echo "║  Version 1.0.0                                                 ║"
  echo "╚════════════════════════════════════════════════════════════════╝"
  echo -e "${NC}"
}

print_step() {
  echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
  echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
  echo -e "${RED}[✗]${NC} $1"
}

print_info() {
  echo -e "${BLUE}[i]${NC} $1"
}

################################################################################
# Validation Functions
################################################################################

check_docker() {
  print_info "Checking Docker installation..."

  if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed"
    echo "Please install Docker: https://docs.docker.com/get-docker/"
    exit 1
  fi

  DOCKER_VERSION=$(docker --version | grep -oP '\d+\.\d+' | head -1)
  print_step "Docker version: ${DOCKER_VERSION}"

  if ! docker info &> /dev/null; then
    print_error "Docker daemon is not running"
    echo "Please start Docker and try again"
    exit 1
  fi

  print_step "Docker is running"
}

check_docker_compose() {
  print_info "Checking Docker Compose installation..."

  if ! command -v docker-compose &> /dev/null; then
    print_error "Docker Compose is not installed"
    echo "Please install Docker Compose: https://docs.docker.com/compose/install/"
    exit 1
  fi

  COMPOSE_VERSION=$(docker-compose --version | grep -oP '\d+\.\d+' | head -1)
  print_step "Docker Compose version: ${COMPOSE_VERSION}"
}

check_system_resources() {
  print_info "Checking system resources..."

  # Check available memory (Linux/macOS)
  if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    TOTAL_MEM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    TOTAL_MEM_GB=$((TOTAL_MEM_KB / 1024 / 1024))
  elif [[ "$OSTYPE" == "darwin"* ]]; then
    TOTAL_MEM_BYTES=$(sysctl -n hw.memsize)
    TOTAL_MEM_GB=$((TOTAL_MEM_BYTES / 1024 / 1024 / 1024))
  else
    print_warning "Unable to determine system memory on this OS"
    TOTAL_MEM_GB=0
  fi

  if [ $TOTAL_MEM_GB -gt 0 ]; then
    print_step "Total system memory: ${TOTAL_MEM_GB} GB"

    if [ $TOTAL_MEM_GB -lt $MIN_MEMORY_GB ]; then
      print_warning "Recommended: ${MIN_MEMORY_GB} GB RAM (you have ${TOTAL_MEM_GB} GB)"
      print_warning "Lab may experience performance issues"
      read -p "Continue anyway? [y/N] " -n 1 -r
      echo
      if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
      fi
    fi
  fi

  # Check available disk space
  AVAILABLE_DISK_GB=$(df -BG "${SCRIPT_DIR}" | awk 'NR==2 {print $4}' | sed 's/G//')
  print_step "Available disk space: ${AVAILABLE_DISK_GB} GB"

  if [ $AVAILABLE_DISK_GB -lt 50 ]; then
    print_warning "Recommended: 50 GB free disk space (you have ${AVAILABLE_DISK_GB} GB)"
  fi
}

check_ports() {
  print_info "Checking required ports..."

  REQUIRED_PORTS=(8000 8089 9200 5601)
  PORT_CONFLICTS=()

  for port in "${REQUIRED_PORTS[@]}"; do
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1 || netstat -tuln 2>/dev/null | grep -q ":$port "; then
      PORT_CONFLICTS+=($port)
      print_warning "Port $port is already in use"
    fi
  done

  if [ ${#PORT_CONFLICTS[@]} -gt 0 ]; then
    print_error "The following ports are in use: ${PORT_CONFLICTS[*]}"
    print_info "Please stop services on these ports or modify docker-compose.yml"
    read -p "Continue anyway? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
      exit 1
    fi
  else
    print_step "All required ports are available"
  fi
}

################################################################################
# Setup Functions
################################################################################

configure_vm_max_map_count() {
  print_info "Configuring vm.max_map_count for Elasticsearch..."

  CURRENT_VALUE=$(sysctl -n vm.max_map_count 2>/dev/null || echo "0")
  REQUIRED_VALUE=262144

  if [ "$CURRENT_VALUE" -lt "$REQUIRED_VALUE" ]; then
    print_warning "Current vm.max_map_count: $CURRENT_VALUE (required: $REQUIRED_VALUE)"

    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
      print_info "Attempting to set vm.max_map_count=$REQUIRED_VALUE"
      if sudo sysctl -w vm.max_map_count=$REQUIRED_VALUE; then
        print_step "vm.max_map_count configured successfully"

        # Make it persistent
        if [ -f /etc/sysctl.conf ]; then
          if ! grep -q "vm.max_map_count" /etc/sysctl.conf; then
            echo "vm.max_map_count=$REQUIRED_VALUE" | sudo tee -a /etc/sysctl.conf > /dev/null
            print_step "vm.max_map_count made persistent in /etc/sysctl.conf"
          fi
        fi
      else
        print_warning "Failed to set vm.max_map_count (requires sudo)"
        print_warning "Elasticsearch may fail to start"
      fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
      print_warning "On macOS, configure vm.max_map_count in Docker Desktop settings"
      print_info "Docker Desktop → Preferences → Resources → Advanced"
    fi
  else
    print_step "vm.max_map_count is already configured: $CURRENT_VALUE"
  fi
}

pull_docker_images() {
  print_info "Pulling Docker images (this may take 10-20 minutes)..."

  cd "${SCRIPT_DIR}"

  if docker-compose pull; then
    print_step "Docker images pulled successfully"
  else
    print_error "Failed to pull Docker images"
    exit 1
  fi
}

start_lab_environment() {
  print_info "Starting lab environment..."

  cd "${SCRIPT_DIR}"

  if docker-compose up -d; then
    print_step "Lab environment started successfully"
  else
    print_error "Failed to start lab environment"
    exit 1
  fi
}

wait_for_services() {
  print_info "Waiting for services to become healthy..."

  # Wait for Splunk
  print_info "Waiting for Splunk (this may take 2-3 minutes)..."
  for i in {1..60}; do
    if curl -k -s https://localhost:8000/en-US/account/login > /dev/null 2>&1; then
      print_step "Splunk is ready"
      break
    fi
    echo -n "."
    sleep 5
  done
  echo

  # Wait for Elasticsearch
  print_info "Waiting for Elasticsearch (this may take 1-2 minutes)..."
  for i in {1..60}; do
    if curl -s -u elastic:Changeme123! http://localhost:9200/_cluster/health > /dev/null 2>&1; then
      print_step "Elasticsearch is ready"
      break
    fi
    echo -n "."
    sleep 5
  done
  echo

  # Wait for Kibana
  print_info "Waiting for Kibana (this may take 1-2 minutes)..."
  for i in {1..60}; do
    if curl -s http://localhost:5601/api/status > /dev/null 2>&1; then
      print_step "Kibana is ready"
      break
    fi
    echo -n "."
    sleep 5
  done
  echo
}

display_access_info() {
  echo
  echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${GREEN}║  Lab Environment Successfully Deployed!                        ║${NC}"
  echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
  echo
  echo -e "${BLUE}Access URLs:${NC}"
  echo -e "  ${GREEN}Splunk Enterprise:${NC}"
  echo -e "    URL:      https://localhost:8000"
  echo -e "    Username: admin"
  echo -e "    Password: Changeme123!"
  echo
  echo -e "  ${GREEN}Kibana (Elastic):${NC}"
  echo -e "    URL:      http://localhost:5601"
  echo -e "    Username: elastic"
  echo -e "    Password: Changeme123!"
  echo
  echo -e "  ${GREEN}Elasticsearch:${NC}"
  echo -e "    URL:      http://localhost:9200"
  echo -e "    Username: elastic"
  echo -e "    Password: Changeme123!"
  echo
  echo -e "${YELLOW}⚠️  SECURITY WARNING:${NC}"
  echo -e "  These are default credentials for LAB USE ONLY"
  echo -e "  Change passwords immediately if exposing to network"
  echo -e "  Do NOT use in production environments"
  echo
  echo -e "${BLUE}Next Steps:${NC}"
  echo -e "  1. Access Splunk and complete initial setup wizard"
  echo -e "  2. Import detection rules:"
  echo -e "     - Splunk: conversions/splunk/all_rules.spl"
  echo -e "     - Elastic: conversions/elastic/all_rules.json"
  echo -e "  3. Review lab documentation: lab/SETUP_GUIDE.md"
  echo -e "  4. Run attack simulations: testing/attack_scenarios.md"
  echo
  echo -e "${BLUE}Useful Commands:${NC}"
  echo -e "  Stop lab:     ${GREEN}docker-compose down${NC}"
  echo -e "  View logs:    ${GREEN}docker-compose logs -f${NC}"
  echo -e "  Restart:      ${GREEN}docker-compose restart${NC}"
  echo -e "  Status:       ${GREEN}docker-compose ps${NC}"
  echo
}

################################################################################
# Cleanup Function
################################################################################

cleanup_on_error() {
  print_error "Setup failed. Cleaning up..."
  cd "${SCRIPT_DIR}"
  docker-compose down -v 2>/dev/null || true
  exit 1
}

################################################################################
# Main Execution
################################################################################

main() {
  trap cleanup_on_error ERR

  print_header

  # Validation phase
  check_docker
  check_docker_compose
  check_system_resources
  check_ports

  echo
  print_info "All prerequisites satisfied"
  echo

  # Confirm deployment
  print_warning "This will deploy a full SIEM lab environment"
  print_info "Required resources: ~16GB RAM, ~30GB disk space"
  print_info "Estimated deployment time: 15-25 minutes"
  echo
  read -p "Proceed with deployment? [Y/n] " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Nn]$ ]]; then
    print_info "Deployment cancelled"
    exit 0
  fi

  echo

  # Setup phase
  configure_vm_max_map_count
  pull_docker_images
  start_lab_environment
  wait_for_services

  # Success
  display_access_info

  print_step "Setup complete!"
}

# Run main function
main "$@"
