# Leegion Framework Makefile
# Provides convenient installation and management commands
#
# Author: Leegion
# Project: Leegion Framework v2.0
# Copyright (c) 2025 Leegion. All rights reserved.

.PHONY: install uninstall clean help test

# Default target
all: help

# Install the framework
install:
	@echo "🚀 Installing Leegion Framework..."
	@sudo python3 leegion_manager.py install

# Uninstall the framework
uninstall:
	@echo "🗑️  Uninstalling Leegion Framework..."
	@sudo python3 leegion_manager.py uninstall

# Reinstall the framework
reinstall:
	@echo "🔄 Reinstalling Leegion Framework..."
	@sudo python3 leegion_manager.py reinstall

# Check installation status
status:
	@echo "📊 Checking installation status..."
	@python3 leegion_manager.py status

# Update the framework
update:
	@echo "🔄 Updating Leegion Framework..."
	@sudo python3 leegion_manager.py update

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	@sudo python3 leegion_manager.py clean

# Test framework functionality
test:
	@echo "🧪 Testing framework..."
	@python3 leegion_manager.py test

# Run tests with coverage
test-coverage:
	@echo "🧪 Running tests with coverage..."
	@python3 -m pytest tests/ --cov=. --cov-report=html --cov-report=term

# Run security tests
test-security:
	@echo "🔒 Running security tests..."
	@python3 -m pytest tests/test_security.py -v

# Run all tests
test-all: test test-coverage test-security

# Development setup
dev-setup:
	@echo "🔧 Setting up development environment..."
	@pip3 install --user python-nmap requests colorama tabulate pyyaml dnspython beautifulsoup4 cryptography

# Package for distribution
package:
	@echo "📦 Creating distribution package..."
	@tar -czf leegion-framework.tar.gz \
	        --exclude='.git*' \
	        --exclude='__pycache__' \
	        --exclude='*.pyc' \
	        --exclude='logs/*' \
	        --exclude='reports/output/*' \
	        --exclude='.cache' \
	        --exclude='.pythonlibs' \
	        --exclude='.upm' \
	        --exclude='uv.lock' \
	        --exclude='.replit' \
	        .
	@echo "✅ Package created: leegion-framework.tar.gz"

# Show help
help:
	@echo "Leegion Framework - Makefile Commands"
	@echo "===================================="
	@echo ""
	@echo "Installation & Management:"
	@echo "  make install       - Install framework system-wide"
	@echo "  make uninstall     - Remove installed framework"
	@echo "  make reinstall     - Reinstall framework (uninstall + install)"
	@echo "  make status        - Check installation status"
	@echo "  make update        - Update framework to latest version"
	@echo "  make clean         - Clean cache and temporary files"
	@echo ""
	@echo "Development:"
	@echo "  make dev-setup     - Setup development environment"
	@echo "  make test          - Test framework functionality"
	@echo "  make test-coverage - Run tests with coverage report"
	@echo "  make test-security - Run security-specific tests"
	@echo "  make test-all      - Run all tests"
	@echo ""
	@echo "Distribution:"
	@echo "  make package       - Create distribution package"
	@echo ""
	@echo "Alternative Management:"
	@echo "  python3 leegion_manager.py menu  - Show interactive menu"
	@echo "  python3 leegion_manager.py help  - Show detailed management options"
	@echo ""
	@echo "Usage after installation:"
	@echo "  leegion           - Run the framework"
	@echo ""