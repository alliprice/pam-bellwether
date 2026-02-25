#!/usr/bin/env bash
set -euo pipefail

# Launch 6 simultaneous SSH connections in a tmux grid.
# Used by VHS demo for the "Ansible moment" act.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/.env"

SESSION="pam-demo"
PANE_COUNT=6

SSH_CMD="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o PubkeyAuthentication=no -o PreferredAuthentications=keyboard-interactive \
    -p $SSH_PORT testuser@127.0.0.1"

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
        "$SSH_CMD 'echo \"[pane ${pane_num}] Connected — no MFA\"; sleep 30'" Enter
done

# Attach to the session
exec tmux attach -t "$SESSION"
