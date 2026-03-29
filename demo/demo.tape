# lancert + Caddy demo
# Requires: vhs (brew install vhs), caddy, jq, curl
# Regenerate: cd demo && vhs demo.tape

Output demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 900
Set Height 500
Set Padding 20
Set Theme "Catppuccin Mocha"
Set WindowBar Colorful
Set TypingSpeed 40ms
Set CursorBlink false

# --- Step 1: Download certs ---

Type "# Step 1: Get a TLS certificate for your local IP"
Enter
Sleep 500ms

Type "curl -sO https://lancert.dev/certs/192.168.0.9/fullchain.pem"
Enter
Sleep 2s

Type "curl -sO https://lancert.dev/certs/192.168.0.9/privkey.pem"
Enter
Sleep 2s

# --- Step 2: Show Caddyfile ---

Type "# Step 2: Caddyfile with lancert certs"
Enter
Sleep 500ms

Type "cat Caddyfile"
Enter
Sleep 2s

# --- Step 3: Start Caddy ---

Type "# Step 3: Start Caddy"
Enter
Sleep 500ms

Type "caddy start 2>/dev/null"
Enter
Sleep 2s

# --- Step 4: Verify HTTPS works ---

Type "# Step 4: Verify HTTPS — base domain and wildcard"
Enter
Sleep 500ms

Type "curl https://192-168-0-9.lancert.dev && echo"
Enter
Sleep 3s

Type "curl https://app.192-168-0-9.lancert.dev && echo"
Enter
Sleep 3s

# --- Cleanup ---

Type "caddy stop 2>/dev/null"
Enter
Sleep 2s

Sleep 1s
