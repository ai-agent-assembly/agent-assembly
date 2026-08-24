#!/usr/bin/env bash
# As fake-hung.sh, but traps and ignores SIGTERM — proves the watchdog's
# escalation to SIGKILL after the grace period, not just the TERM step.
set -u
trap '' TERM
sleep 3600
