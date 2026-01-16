# Change Ideas / Known Issues

## Known Issues

- **Narrow sidebar on mobile** - Pinned sidebar is too narrow for comfortable terminal use. Use full-width mode instead.
- **Unknown characters on Android** - Some box-drawing characters (╭╮╯╰) may show as diamonds on Android tablets. Font limitation.
- **Voice input preview** - Android voice input shows composition preview below input (normal IME behavior, looks odd)

## Potential Improvements

### Network / Connection
- WebSocket drops silently when mobile goes to sleep — client thinks it's connected but isn't
- Reconnection UX — what happens when you reopen Obsidian after hours?
- Server crash detection — plugin doesn't know if relay_server.py crashed

### UX
- Swipe-to-open sidebar behavior (currently only toggle/pin works)
- Auto-detect landscape mode and hide arrow controls when keyboard connected
- Better error messages when Tailscale not connected

### Server
- Mac sleep despite caffeinate (lid close, power settings)
- LaunchAgent for auto-starting relay on Mac login

## Completed

- ~~Drop LAN Mode + token auth~~ - Now Tailscale-only
- ~~Multiple devices killing each other's sessions~~ - Each connection now gets its own Claude session
- ~~Token sync issues~~ - Removed token auth entirely
- ~~Mobile settings overwriting desktop settings~~ - Mobile now read-only
