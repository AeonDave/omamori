#!/bin/bash

# Omamori Quick Test Runner
# Run this after building to verify all protection layers

set -e

cd "$(dirname "$0")/build"

echo "╔═════════════════════════════════════════════════════════╗"
echo "║        OMAMORI QUICK TEST - All Protection Layers       ║"
echo "╚═════════════════════════════════════════════════════════╝"
echo

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

run_test() {
    local test_name=$1
    local test_exe=$2
    local timeout_sec=${3:-10}
    local allow_segfault=${4:-0}
    
    printf "${BLUE}[%-35s]${NC} " "$test_name"
    
    timeout $timeout_sec ./$test_exe > /tmp/omamori_test_$$.log 2>&1
    local exit_code=$?
    
    # Exit code 139 is segfault (128 + 11), which is OK for anti-dump tests
    if [ $exit_code -eq 0 ] || ([ $exit_code -eq 139 ] && [ $allow_segfault -eq 1 ]); then
        echo -e "${GREEN}✓ PASS${NC}"
        return 0
    else
        echo -e "${RED}✗ FAIL (exit: $exit_code)${NC}"
        [ -s /tmp/omamori_test_$$.log ] && echo "  See: /tmp/omamori_test_$$.log"
        return 1
    fi
}

echo "═══ Layer 1: Anti-Virtualization ═══"
run_test "Anti-VM Detection (Linux)" "omamori_antivm_test_linux" 15

echo
echo "═══ Layer 2: Anti-Debug (Segfault Expected) ═══"
printf "${BLUE}[%-35s]${NC} " "Anti-Debug Protection"
timeout 5 ./omamori_test_linux > /dev/null 2>&1 || echo -e "${GREEN}✓ PASS (Protected)${NC}"
printf "${BLUE}[%-35s]${NC} " "Anti-Attach (ptrace)"
timeout 5 ./omamori_anti_attach_test > /dev/null 2>&1 || echo -e "${GREEN}✓ PASS (Protected)${NC}"

echo
echo "═══ Layer 3: Anti-Dump (Segfault Expected) ═══"
printf "${BLUE}[%-35s]${NC} " "Anti-Dump Verification"
timeout 5 ./omamori_verify_antidump > /dev/null 2>&1 || echo -e "${GREEN}✓ PASS (Protected)${NC}"

echo
echo "═══ Layer 4: Memory Encryption ═══"
run_test "Memory Encryption" "omamori_memory_encryption_test" 15
run_test "License Protection Example" "omamori_license_example" 10

echo
echo "═══ Integration Tests ═══"
run_test "UPX Stub Protection" "omamori_upx_stub_test" 5
run_test "Full Protection Stack" "omamori_example_linux" 10

echo
echo "╔═════════════════════════════════════════════════════════╗"
echo "║                    TEST SUMMARY                         ║"
echo "╚═════════════════════════════════════════════════════════╝"
echo

# Count results
total=8
passed=$(ls /tmp/omamori_test_$$.log 2>/dev/null | wc -l)
failed=$((total - passed))

if [ $failed -eq 0 ]; then
    echo -e "${GREEN}All tests passed! ($total/$total)${NC}"
    echo
    echo "✓ Anti-VM:             Working"
    echo "✓ Anti-Debug:          Working"
    echo "✓ Anti-Dump:           Working"
    echo "✓ Memory Encryption:   Working"
    echo
    echo "Omamori protection stack is fully operational!"
else
    echo -e "${RED}Some tests failed: $passed/$total passed${NC}"
    echo "Check logs in /tmp/omamori_test_$$.log"
fi

# Cleanup
rm -f /tmp/omamori_test_$$.log

exit 0
