#!/usr/bin/env bash
# A genuinely hung job: sleeps indefinitely, no log growth, no CPU, no
# child-process transitions. Honors SIGTERM (the default disposition), so
# the watchdog's graceful-then-forceful ladder terminates it at the TERM
# step.
set -u
sleep 3600
