#!/usr/bin/env bash
# Start a virtual X display, then exec the command so the real process is PID 1 and
# receives signals (docker stop, timeouts). xvfb-run is deliberately avoided: as a
# container entrypoint it hangs (it traps signals and never forwards them, so the
# container ignores SIGTERM). Here Xvfb is a background child and `exec "$@"` hands PID 1
# to the actual runner.
set -e

: "${SAGE_XVFB_DISPLAY:=:99}"
Xvfb "$SAGE_XVFB_DISPLAY" -screen 0 1280x1024x24 -nolisten tcp >/tmp/xvfb.log 2>&1 &
export DISPLAY="$SAGE_XVFB_DISPLAY"

# Wait for the X socket to appear before handing off (Electron needs the display ready).
for _ in $(seq 1 50); do
  [ -S "/tmp/.X11-unix/X${SAGE_XVFB_DISPLAY#:}" ] && break
  sleep 0.1
done

exec "$@"
