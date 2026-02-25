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
Type "# pam-preauth: MFA caching for SSH"
Enter
Type "# Problem: Ansible opens 50 connections → 50 MFA prompts"
Enter
Type "# Solution: first connection does MFA, the rest sail through"
Enter
Sleep 3s

# Act 1: Cache miss — first SSH triggers MFA
Type "# Act 1: First connection (cache miss → MFA prompt)"
Enter
Sleep 1s
Type "./demo/ssh-totp.sh"
Enter
Sleep 10s

# Act 2: Cache hit — second SSH skips MFA
Type "# Act 2: Second connection (cache hit → no MFA)"
Enter
Sleep 1s
Type "./demo/ssh-cached.sh"
Enter
Sleep 6s

# Act 3: Concurrent connections via tmux
Type "# Act 3: 6 simultaneous connections (the Ansible moment)"
Enter
Sleep 1s
Type "./demo/concurrent.sh"
Enter
Sleep 8s

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

Type "echo 'All connections authenticated — only 1 MFA prompt total.'"
Enter
Sleep 3s
