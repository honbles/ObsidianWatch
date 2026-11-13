#!/bin/bash
# ObsidianWatch Alert Graph test — HARMLESS. Runs a shell -> download -> staged
# binary in /tmp -> outbound connection chain that keeps every process alive for
# ~45s (the Linux agent polls, so very short-lived processes can be missed).
# It only fetches example.com, copies /bin/sleep to /tmp and opens one socket.
# Expected alerts: "Shell Suspicious Execution" (T1059.004) and
# "Executable Run from /tmp" (T1059.004). Then open the alert -> Graph tab.
set -u
CMD='curl -s -o /tmp/ow_graph_dl.txt https://example.com/; cp /bin/sleep /tmp/ow_graph_stage; /tmp/ow_graph_stage 45 & python3 -c "import socket,time; s=socket.create_connection((\"example.com\",443)); time.sleep(45)"; wait'
bash -c "$CMD"
rm -f /tmp/ow_graph_dl.txt /tmp/ow_graph_stage
echo "done - wait ~1-2 min, then open the new alert on this host and click Graph"
