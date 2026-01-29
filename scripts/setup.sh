#!/bin/bash

# CloudHawk Setup Script
# This script helps you get CloudHawk up and running

set -e

echo "🦅 CloudHawk Setup Script"
echo "=========================="
echo ""

# Check Docker
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

echo "✅ Docker and Docker Compose are installed"
echo ""

# Check system resources
echo "📊 Checking system resources..."
TOTAL_MEM=$(free -g | awk '/^Mem:/{print $2}')
if [ "$TOTAL_MEM" -lt 6 ]; then
    echo "⚠️  Warning: System has less than 6GB RAM. CloudHawk may run slowly."
    echo "   Recommended: 8GB+ RAM"
else
    echo "✅ Sufficient memory available"
fi
echo ""

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p data/{timescale,redis,elasticsearch,prometheus,grafana}
echo "✅ Directories created"
echo ""

# Pull images
echo "📥 Pulling Docker images (this may take a few minutes)..."
docker-compose pull
echo "✅ Images pulled"
echo ""

# Build custom services
echo "🔨 Building CloudHawk services..."
docker-compose build
echo "✅ Services built"
echo ""

# Start services
echo "🚀 Starting CloudHawk..."
docker-compose up -d

echo ""
echo "⏳ Waiting for services to initialize (60 seconds)..."
sleep 60

echo ""
echo "=========================="
echo "✅ CloudHawk is running!"
echo "=========================="
echo ""
echo "🌐 Access points:"
echo "   Dashboard:     http://localhost:3000"
echo "   API Docs:      http://localhost:8000/docs"
echo "   Grafana:       http://localhost:3001 (admin/admin)"
echo "   Prometheus:    http://localhost:9090"
echo ""
echo "📊 Check status:"
echo "   docker-compose ps"
echo ""
echo "📝 View logs:"
echo "   docker-compose logs -f"
echo ""
echo "🛑 Stop CloudHawk:"
echo "   docker-compose down"
echo ""
echo "Happy hunting! 🦅"
