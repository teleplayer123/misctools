#!/bin/bash

# Refresh interval (seconds)
INTERVAL=2

echo "Apple Silicon Memory Monitor (press Ctrl+C to quit)"
echo "---------------------------------------------------"

while true; do
    # Get page size (bytes)
    PAGE_SIZE=$(vm_stat | grep "page size of" | awk '{print $8}')

    # Extract vm_stat values
    FREE_PAGES=$(vm_stat | grep "Pages free" | awk '{print $3}' | tr -d '.')
    ACTIVE_PAGES=$(vm_stat | grep "Pages active" | awk '{print $3}' | tr -d '.')
    INACTIVE_PAGES=$(vm_stat | grep "Pages inactive" | awk '{print $3}' | tr -d '.')
    WIRED_PAGES=$(vm_stat | grep "Pages wired down" | awk '{print $4}' | tr -d '.')

    # Convert to MB
    FREE_MB=$((FREE_PAGES * PAGE_SIZE / 1024 / 1024))
    ACTIVE_MB=$((ACTIVE_PAGES * PAGE_SIZE / 1024 / 1024))
    INACTIVE_MB=$((INACTIVE_PAGES * PAGE_SIZE / 1024 / 1024))
    WIRED_MB=$((WIRED_PAGES * PAGE_SIZE / 1024 / 1024))

    # Get memory pressure info
    PRESSURE=$(memory_pressure | grep "System-wide memory free percentage" | awk '{print $5}')

    # Get swap usage
    SWAP=$(sysctl vm.swapusage | awk '{print $3 " used / " $6 " total"}')

    # Clear screen
    clear

    echo "==== Memory Stats ===="
    echo "Free:      ${FREE_MB} MB"
    echo "Active:    ${ACTIVE_MB} MB"
    echo "Inactive:  ${INACTIVE_MB} MB"
    echo "Wired:     ${WIRED_MB} MB"
    echo ""
    echo "==== System Info ===="
    echo "Memory Pressure (free %): ${PRESSURE}"
    echo "Swap Usage: ${SWAP}"
    echo ""
    echo "Updated: $(date)"

    sleep $INTERVAL
done