#!/usr/bin/env bash
# Post-deploy checks. Run on the VPS.
set -u
fail=0
chk() { if eval "$2" >/dev/null 2>&1; then echo "ok   $1"; else echo "FAIL $1"; fail=1; fi; }

chk "strait-host active" "systemctl is-active --quiet strait-host"
chk "UDP 7100 listening" "ss -lunH | grep -q ':7100 '"
chk "host.env is 0600" "[ \"\$(stat -c %a /etc/strait/host.env)\" = 600 ]"
chk "lab key absent" "! grep -q 0123456789abcdef0123456789abcdef /etc/strait/host.env"
chk "unit has no --relay" "! systemctl cat strait-host | grep -q -- --relay"
if systemctl is-enabled --quiet strait-signal 2>/dev/null || systemctl is-active --quiet strait-signal; then
  echo "note strait-signal is enabled/active (optional; not default)"
  chk "UDP 7000 listening" "ss -lunH | grep -q ':7000 '"
else
  echo "ok   strait-signal not running (default)"
fi
echo
echo "Manual: during a direct phone->VPS session, 'journalctl -u strait-signal' must be empty"
echo "(done when the signal log has no entries for the session, per M4)."
exit $fail
