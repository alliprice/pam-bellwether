# Act 2: 6 simultaneous cold connections — the serialization demo
# Record: vhs demo/act2.tape

Output demo/act2.gif

Set FontSize 20
Set Width 1400
Set Height 800
Set Theme "Catppuccin Mocha"
Set TypingSpeed 10ms

Type "# --- Act 2: 6 connections at once (the Ansible moment) ---"
Enter
Sleep 1s
Set TypingSpeed 50ms
Type "./demo/concurrent.sh"
Enter
Sleep 18s

# Detach from tmux
Ctrl+b
Type "d"
Sleep 1s

# Hidden cleanup
Hide
Type "tmux kill-session -t pam-demo 2>/dev/null; true"
Enter
Sleep 1s
Type "clear"
Enter
Sleep 0.5s
Show

Set TypingSpeed 10ms
Type "echo '6 connections. 1 MFA prompt. 5 queued behind the lock, served from cache.'"
Enter
Sleep 3s
