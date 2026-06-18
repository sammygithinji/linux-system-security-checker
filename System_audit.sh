#!/bin/bash
# system_audit.sh
# Linux system security audit script.
# Run as root for complete results.
# Usage: sudo bash system_audit.sh

REPORT_DIR="./reports"
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
REPORT="$REPORT_DIR/system_audit_$TIMESTAMP.txt"

mkdir -p "$REPORT_DIR"

if [ "$EUID" -ne 0 ]; then
    echo ""
    echo "WARNING: Run this script as root for complete results."
    echo ""
    exit 1
fi


echo "  LINUX SYSTEM SECURITY AUDIT REPORT"                             | tee -a "$REPORT"
echo ""
echo "  Date     : $(date)"                                              | tee -a "$REPORT"
echo "  Host     : $(hostname)"                                          | tee -a "$REPORT"
echo "  Auditor  : $(whoami)"                                            | tee -a "$REPORT"
echo""

#Section 1: System Information

echo ""                                                  | tee -a "$REPORT"
echo "--- SECTION 1: SYSTEM INFORMATION ---"             | tee -a "$REPORT"
echo ""                                                  | tee -a "$REPORT"
echo "  Hostname       : $(hostname)"                    | tee -a "$REPORT"
echo "  Kernel         : $(uname -r)"                    | tee -a "$REPORT"
echo "  OS             : $(cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')" | tee -a "$REPORT"
echo "  Uptime         : $(uptime -p)"                   | tee -a "$REPORT"
echo "  IP Address     : $(hostname -I | awk '{print $1}')"             | tee -a "$REPORT"
echo "  Logged-in users: $(who | wc -l)"                | tee -a "$REPORT"


# Section 2: Failed Login Attempts


echo ""                                                  | tee -a "$REPORT"
echo "--- SECTION 2: FAILED LOGIN ATTEMPTS ---"          | tee -a "$REPORT"
echo ""                                                  | tee -a "$REPORT"

# Debian/Ubuntu use auth.log; RHEL/CentOS use secure
if [ -f /var/log/auth.log ]; then
    AUTH_LOG="/var/log/auth.log"
elif [ -f /var/log/secure ]; then
    AUTH_LOG="/var/log/secure"
else
    echo "  WARNING: No auth log found. Skipping this check." | tee -a "$REPORT"
    AUTH_LOG=""
fi

if [ -n "$AUTH_LOG" ]; then
    FAIL_COUNT=$(grep -c "Failed password" "$AUTH_LOG" 2>/dev/null || echo 0)
    echo "  Auth log       : $AUTH_LOG"                  | tee -a "$REPORT"
    echo "  Failed logins  : $FAIL_COUNT"                | tee -a "$REPORT"

    if [ "$FAIL_COUNT" -gt 0 ]; then
        echo ""                                          | tee -a "$REPORT"
        echo "  Top offending IPs:"                     | tee -a "$REPORT"
        grep "Failed password" "$AUTH_LOG" | grep -oE "from [0-9.]+" | sort | uniq -c | sort -rn | head -10 | while read -r line; do
            echo "    $line"                             | tee -a "$REPORT"
        done

        echo ""                                          | tee -a "$REPORT"
        echo "  Last 5 failed login events:"            | tee -a "$REPORT"
        grep "Failed password" "$AUTH_LOG" | tail -5 | while read -r line; do
            echo "    $line"                             | tee -a "$REPORT"
        done
    fi
fi


# Section 3: Open Ports and Listening Services


echo ""                                                  | tee -a "$REPORT"
echo "--- SECTION 3: OPEN PORTS AND LISTENING SERVICES ---" | tee -a "$REPORT"
echo ""                                                  | tee -a "$REPORT"

# ss shows active network sockets; -tulnp = TCP, UDP, listening, numeric, with process
ss -tulnp                                               | tee -a "$REPORT"

# Check for commonly risky ports
echo ""                                                  | tee -a "$REPORT"
echo "  High-risk port check:"                          | tee -a "$REPORT"

for PORT in 21 23 25 110 135 139 445 3389; do
    if ss -tulnp | grep -q ":$PORT "; then
        echo "  [FINDING] Port $PORT is open. Verify this is intentional." | tee -a "$REPORT"
    fi
done


# Section 4: Running Services


echo ""                                                  | tee -a "$REPORT"
echo "--- SECTION 4: RUNNING SERVICES ---"               | tee -a "$REPORT"
echo ""                                                  | tee -a "$REPORT"

systemctl list-units --type=service --state=running --no-legend | tee -a "$REPORT"


# Section 5: SUID Files


echo ""                                                  | tee -a "$REPORT"
echo "--- SECTION 5: SUID FILES ---"                     | tee -a "$REPORT"
echo "  (Files that run with the owner's privileges)"    | tee -a "$REPORT"
echo ""                                                  | tee -a "$REPORT"

# -xdev skips other filesystems (avoids /proc, /sys, NFS mounts)
find / -xdev -perm /4000 -type f 2>/dev/null | while read -r FILE; do
    ls -lh "$FILE"                                      | tee -a "$REPORT"
done


# Section 6: SGID Files


echo ""                                                  | tee -a "$REPORT"
echo "--- SECTION 6: SGID FILES ---"                     | tee -a "$REPORT"
echo "  (Files that run with the group's privileges)"    | tee -a "$REPORT"
echo ""                                                  | tee -a "$REPORT"

find / -xdev -perm /2000 -type f 2>/dev/null | while read -r FILE; do
    ls -lh "$FILE"                                      | tee -a "$REPORT"
done


# Section 7: World-Writable Files and Directories


echo ""                                                  | tee -a "$REPORT"
echo "--- SECTION 7: WORLD-WRITABLE FILES ---"           | tee -a "$REPORT"
echo "  (Any user on the system can modify these files)" | tee -a "$REPORT"
echo ""                                                  | tee -a "$REPORT"

find / -xdev -perm /o+w -type f ! -path "*/proc/*" ! -path "*/sys/*" 2>/dev/null | while read -r FILE; do
    ls -lh "$FILE"                                      | tee -a "$REPORT"
done

echo ""                                                  | tee -a "$REPORT"
echo "--- SECTION 7b: WORLD-WRITABLE DIRECTORIES ---"    | tee -a "$REPORT"
echo "  (Excluding /tmp and /var/tmp which are intentionally world-writable)" | tee -a "$REPORT"
echo ""                                                  | tee -a "$REPORT"

find / -xdev -perm /o+w -type d ! -path "*/proc/*" ! -path "*/sys/*" ! -path "*/tmp*" 2>/dev/null | while read -r DIR; do
    ls -ldh "$DIR"                                      | tee -a "$REPORT"
done


# Recommendations


echo ""                                                  | tee -a "$REPORT"
echo "--- RECOMMENDATIONS ---"                           | tee -a "$REPORT"
echo ""                                                  | tee -a "$REPORT"
echo "  1. Failed logins: Review the top IPs above."    | tee -a "$REPORT"
echo "     Consider using fail2ban to block repeat offenders." | tee -a "$REPORT"
echo "     Disable SSH password auth and use key-based login instead." | tee -a "$REPORT"
echo ""                                                  | tee -a "$REPORT"
echo "  2. Open ports: Close or firewall ports that are not needed." | tee -a "$REPORT"
echo "     Use ufw or firewalld to restrict access."    | tee -a "$REPORT"
echo ""                                                  | tee -a "$REPORT"
echo "  3. Services: Disable any service not required."  | tee -a "$REPORT"
echo "     Command: systemctl disable <service-name>"    | tee -a "$REPORT"
echo ""                                                  | tee -a "$REPORT"
echo "  4. SUID/SGID: Remove the bit from files that don't need it." | tee -a "$REPORT"
echo "     Command: chmod u-s <file>  or  chmod g-s <file>" | tee -a "$REPORT"
echo ""                                                  | tee -a "$REPORT"
echo "  5. World-writable files: Remove the write bit where not needed." | tee -a "$REPORT"
echo "     Command: chmod o-w <file>"                    | tee -a "$REPORT"
echo ""                                                  | tee -a "$REPORT"
echo "  6. Keep the system patched: apt upgrade / yum update" | tee -a "$REPORT"
echo "     Harden SSH in /etc/ssh/sshd_config:"         | tee -a "$REPORT"
echo "       PermitRootLogin no"                         | tee -a "$REPORT"
echo "       PasswordAuthentication no"                  | tee -a "$REPORT"


