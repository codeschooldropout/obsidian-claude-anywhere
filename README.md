# Claude Anywhere

Run Claude Code on your tablet via Tailscale.

## Requirements

- Mac with Claude Code installed
- Tailscale on all devices (same account)
- Physical keyboard (Bluetooth or attached)

## Setup

### Mac (Server)

1. Install Tailscale, sign in: https://tailscale.com/download
2. Install this plugin in Obsidian
3. Go to Settings → Claude Anywhere
4. Enable "Remote Access"
5. Keep Mac awake:
   ```bash
   caffeinate -d -i -s
   ```

### Tablet (Client)

1. Install Tailscale, sign in (same account as Mac)
2. Install plugin via Obsidian Sync (same vault)
3. Connect physical keyboard
4. Open Claude Anywhere from the ribbon icon or command palette

## Usage

### Opening Claude

- **Ribbon icon** - Click the brain icon
- **Command palette** - Search "Claude":
  - "Open Claude Code" - Opens or focuses existing terminal
  - "New Claude Tab (Sidebar)" - Opens in right sidebar
  - "New Claude Tab (Full Width)" - Opens as main content tab (recommended for mobile)

### Mobile Controls

Arrow keys and special buttons appear at the bottom:
- **← ↓ ↑ →** - Arrow key navigation
- **Esc** - Escape key (for vim mode, canceling)
- **Enter** - Submit/confirm

### Multiple Terminals

You can have multiple Claude terminals open at once. Each gets its own independent session.

## Architecture

```
Tablet                          Mac
┌─────────────────┐             ┌─────────────────┐
│ Obsidian        │  Tailscale  │ Obsidian        │
│ + Plugin        │◄───────────►│ + Plugin        │
│ + xterm.js      │   (secure)  │ + relay_server  │
│ + Keyboard      │             │ + Claude Code   │
└─────────────────┘             └─────────────────┘

Connection: ws://100.x.x.x:8765 (Tailscale IP)
```

## Session Behavior

**On disconnect:** Claude session is killed (prevents orphan processes)

**To continue a conversation:** Use Claude's `/resume` command after reconnecting.

## Known Limitations

- **Narrow sidebar** - Mobile pinned sidebar is too narrow. Use "Full Width" mode instead.
- **Physical keyboard required** - Claude Code is keyboard-first
- **Some Android fonts** - Box-drawing characters may show as diamonds on some devices

## Files

- `main.js` - Bundled Obsidian plugin
- `relay_server.py` - Python WebSocket relay (no external deps)
- `manifest.json` - Plugin metadata
- `styles.css` - Terminal styling

## Troubleshooting

**"Connection failed"**
- Check Tailscale is connected on both devices
- Check server is running (Settings → Claude Anywhere on Mac)
- Try toggling Remote Access off/on

**Terminal text garbled**
- Close any duplicate terminal tabs
- Restart the server (toggle Remote Access)
