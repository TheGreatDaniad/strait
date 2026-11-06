#!/bin/bash
# Test runner script for NAT Tunnel

set -e

PROJECT_DIR="/Users/you/Documents/Default/Project/nat-tunnel"

# Change to project directory
cd "$PROJECT_DIR"

# Check if Cargo is installed
if ! command -v cargo &> /dev/null; then
    echo "Error: Cargo not found. Please install Rust."
    exit 1
fi

# Build the project
echo "Building project..."
cargo build --release

# Run integration tests
echo ""
echo "Running integration tests..."
cargo test -- --test harness

# Run network simulation tests
echo ""
echo "Running network simulation tests..."
cargo test -- --test simulation

# Print test results
echo ""
echo "=== Test Summary ==="
echo "All tests completed successfully!"
