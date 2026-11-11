#!/usr/bin/env bash
# ==============================================================================
# mini-firewall Automated Validation & Test Suite
# Author: Albert Adamyan <albertadaman70@gmail.com>
# ==============================================================================

set -euo pipefail

COLOR_GREEN="\033[0;32m"
COLOR_RED="\033[0;31m"
COLOR_YELLOW="\033[0;33m"
COLOR_CYAN="\033[0;36m"
COLOR_RESET="\033[0m"

FWCTL="./cli/fwctl"
PROC_FILE="/proc/mini_firewall"
PASS_COUNT=0
TOTAL_TESTS=5

log_info() {
    echo -e "${COLOR_CYAN}[INFO]${COLOR_RESET} $1"
}

log_pass() {
    echo -e "${COLOR_GREEN}[PASS]${COLOR_RESET} $1"
    PASS_COUNT=$((PASS_COUNT + 1))
}

log_fail() {
    echo -e "${COLOR_RED}[FAIL]${COLOR_RESET} $1"
    exit 1
}

echo -e "${COLOR_YELLOW}======================================================${COLOR_RESET}"
echo -e "${COLOR_YELLOW}   Running mini-firewall Kernel & CLI Test Suite      ${COLOR_RESET}"
echo -e "${COLOR_YELLOW}======================================================${COLOR_RESET}"

# 0. Pre-flight checks
if [[ $EUID -ne 0 ]]; then
   log_fail "This test suite must be run as root (use sudo)!"
fi

if [[ ! -f "$PROC_FILE" ]]; then
   log_fail "Module not loaded! /proc/mini_firewall does not exist. Run 'make load' first."
fi

if [[ ! -x "$FWCTL" ]]; then
   log_info "Building CLI utility..."
   make -C cli
fi

# Reset initial state
$FWCTL clear
$FWCTL reset-stats

# ------------------------------------------------------------------------------
# Test 1: Baseline connectivity
# ------------------------------------------------------------------------------
log_info "Test 1: Baseline ICMP (ping) connectivity..."
if ping -c 1 -W 1 127.0.0.1 > /dev/null 2>&1; then
    log_pass "Baseline traffic allowed without rules."
else
    log_fail "Baseline ping failed before applying rules!"
fi

# ------------------------------------------------------------------------------
# Test 2: ICMP Stealth Mode (Protocol Blocking)
# ------------------------------------------------------------------------------
log_info "Test 2: Blocking ICMP protocol..."
$FWCTL block proto icmp

if ping -c 1 -W 1 127.0.0.1 > /dev/null 2>&1; then
    log_fail "Ping succeeded when ICMP should be dropped!"
else
    log_pass "ICMP packet successfully dropped by kernel hook!"
fi

# Verify counter in procfs
DROPS=$(grep "Drops by Protocol:" "$PROC_FILE" | awk '{print $4}')
if [[ "$DROPS" -ge 1 ]]; then
    log_pass "Kernel stats verified: Protocol drop counter incremented ($DROPS)."
else
    log_fail "Kernel counter did not increment!"
fi

# Clear ICMP block
$FWCTL clear

# ------------------------------------------------------------------------------
# Test 3: TCP Port Filter
# ------------------------------------------------------------------------------
TEST_PORT=54321
log_info "Test 3: Blocking TCP Destination Port $TEST_PORT..."
$FWCTL block port $TEST_PORT tcp

# Check rules table
if $FWCTL status | grep -q "BLOCK TCP PORT: $TEST_PORT"; then
    log_pass "Rule correctly registered in kernel rule table."
else
    log_fail "Port blocking rule not found in kernel table!"
fi

# Start dummy listener in background
nc -l -p $TEST_PORT > /dev/null 2>&1 &
NC_PID=$!
sleep 0.2

# Try to connect with timeout
if nc -z -w 1 127.0.0.1 $TEST_PORT > /dev/null 2>&1; then
    kill -9 $NC_PID 2>/dev/null || true
    log_fail "Connection on port $TEST_PORT succeeded when it should be blocked!"
else
    kill -9 $NC_PID 2>/dev/null || true
    log_pass "TCP connection to port $TEST_PORT dropped by Netfilter!"
fi

# ------------------------------------------------------------------------------
# Test 4: Scan Detector Toggle
# ------------------------------------------------------------------------------
log_info "Test 4: TCP Anomaly & Port Scan Detector Toggle..."
$FWCTL scan-detect on
if grep -q "Scan detection: ENABLED" "$PROC_FILE"; then
    log_pass "Scan detection toggle enabled successfully."
else
    log_fail "Failed to enable scan detection."
fi

# ------------------------------------------------------------------------------
# Test 5: Clean rule reset & teardown
# ------------------------------------------------------------------------------
log_info "Test 5: Resetting rules and checking restoration..."
$FWCTL clear
if ping -c 1 -W 1 127.0.0.1 > /dev/null 2>&1; then
    log_pass "Traffic fully restored after clearing rules."
else
    log_fail "Traffic still blocked after clear!"
fi

echo -e "\n${COLOR_GREEN}======================================================${COLOR_RESET}"
echo -e "${COLOR_GREEN}   ALL TESTS PASSED! ($PASS_COUNT/$TOTAL_TESTS)                        ${COLOR_RESET}"
echo -e "${COLOR_GREEN}   mini-firewall is operational, verified, and stable.   ${COLOR_RESET}"
echo -e "${COLOR_GREEN}======================================================${COLOR_RESET}"
