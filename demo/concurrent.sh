#!/usr/bin/env bash
set -euo pipefail

# Launch 6 simultaneous cold SSH connections in a tmux grid.
# Clears cache first so one connection gets MFA, five queue behind the flock.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/.env"

SESSION="pam-demo"
PANE_COUNT=6

# Clear cache so all connections start cold
limactl shell pam-preauth -- sudo rm -f /run/pam-preauth/*.token /run/pam-preauth/*.lock
echo "Clearing MFA cache..."
sleep 1
echo "Launching $PANE_COUNT simultaneous connections..."
sleep 1

# Kill any existing session
tmux kill-session -t "$SESSION" 2>/dev/null || true

# Create session with first pane
tmux new-session -d -s "$SESSION" -x 170 -y 40

# Create remaining panes
for i in $(seq 2 $PANE_COUNT); do
    tmux split-window -t "$SESSION"
    tmux select-layout -t "$SESSION" tiled
done

# Send SSH commands to all panes simultaneously
for i in $(seq 0 $((PANE_COUNT - 1))); do
    pane_num=$((i + 1))
    tmux send-keys -t "${SESSION}:0.${i}" \
        "$SCRIPT_DIR/ssh-attempt.sh --label $pane_num" Enter
done

# Attach to the session
exec tmux attach -t "$SESSION"
