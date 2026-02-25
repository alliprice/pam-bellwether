# VHS tape file for pam-preauth demo
# Record: vhs demo/demo.tape
# Output: demo/pam-preauth-demo.gif

Output demo/pam-preauth-demo.gif

Set FontSize 20
Set Width 1400
Set Height 800
Set Theme "Catppuccin Mocha"
Set TypingSpeed 50ms

# Title card
Type "# pam-preauth: serialize and cache SSH MFA"
Enter
Type "# When Ansible opens 50 connections, only the 1st triggers MFA."
Enter
Type "# The rest queue behind a lock, then use the cached result."
Enter
Sleep 3s

# Act 1: single cold connection
Type "# --- Act 1: Single connection, cold cache ---"
Enter
Sleep 1s
Type "./demo/ssh-attempt.sh"
Enter
Sleep 12s

# Act 2: 6 cold simultaneous connections
Type "# --- Act 2: 6 connections at once (the Ansible moment) ---"
Enter
Sleep 1s
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
Show

# Summary
Type "echo '6 connections. 1 MFA prompt. 5 queued behind the lock, served from cache.'"
Enter
Sleep 3s
