# pam-preauth demo: MFA caching + flock serialization
# Record: vhs demo/act1.tape

Output demo/pam-preauth-demo.gif

Set FontSize 20
Set Width 1400
Set Height 800
Set Theme "Catppuccin Mocha"
Set TypingSpeed 10ms

# Hidden setup: clear cache and clean the terminal
Hide
Type "limactl shell pam-preauth -- sudo bash -c 'rm -f /run/pam-preauth/*.token /run/pam-preauth/*.lock'"
Enter
Sleep 2s
Type "clear"
Enter
Sleep 0.5s
Show

# Title card
Type "# pam-preauth: serialize and cache SSH MFA"
Enter
Type "# When Ansible opens 50 connections, only the 1st triggers MFA."
Enter
Type "# The rest queue behind a lock, then use the cached result."
Enter
Sleep 3s

# Act 1: caching — cold then warm
Type "# --- Act 1: First connection (cold cache → MFA prompt) ---"
Enter
Sleep 1s
Set TypingSpeed 50ms
Type "./demo/ssh-attempt.sh"
Enter
Sleep 15s

Set TypingSpeed 10ms
Type "# --- Second connection (warm cache → no MFA) ---"
Enter
Sleep 1s
Set TypingSpeed 50ms
Type "./demo/ssh-attempt.sh"
Enter
Sleep 8s

