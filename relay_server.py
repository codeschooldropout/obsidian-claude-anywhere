#!/usr/bin/env python3
"""
Claude Anywhere Relay Server

WebSocket server that bridges remote clients to Claude Code CLI via PTY.
Run this on your Mac, connect from any device with the modified Obsidian plugin.
"""

import asyncio
import json
import os
import pty
import signal
import struct
import fcntl
import termios
import websockets
from websockets.server import serve

# Configuration
HOST = "0.0.0.0"  # Listen on all interfaces
PORT = 8765
CLAUDE_CMD = ["claude"]  # The command to run

class ClaudeSession:
    """Manages a single Claude Code PTY session."""

    def __init__(self):
        self.master_fd = None
        self.pid = None
        self.websocket = None
        self.read_task = None

    async def start(self, websocket, cwd=None):
        """Spawn Claude Code in a PTY and start relaying."""
        self.websocket = websocket

        # Create PTY
        self.master_fd, slave_fd = pty.openpty()

        # Fork process
        self.pid = os.fork()

        if self.pid == 0:
            # Child process: become Claude Code
            os.close(self.master_fd)
            os.setsid()
            os.dup2(slave_fd, 0)  # stdin
            os.dup2(slave_fd, 1)  # stdout
            os.dup2(slave_fd, 2)  # stderr
            os.close(slave_fd)

            # Change to vault directory if provided
            if cwd:
                # If path is relative (e.g., just "exec" from mobile), look in ~/Github/
                if not os.path.isabs(cwd):
                    base_paths = [
                        os.path.expanduser(f"~/Github/{cwd}"),
                        os.path.expanduser(f"~/{cwd}"),
                        cwd
                    ]
                    for try_path in base_paths:
                        if os.path.isdir(try_path):
                            cwd = try_path
                            break
                try:
                    os.chdir(cwd)
                except OSError:
                    pass  # Fall back to current dir if path invalid

            # Set TERM for proper terminal handling
            os.environ["TERM"] = "xterm-256color"

            # Execute Claude
            os.execvp(CLAUDE_CMD[0], CLAUDE_CMD)
        else:
            # Parent process: relay I/O
            os.close(slave_fd)

            # Keep blocking mode - we use select() to know when data is ready
            # Start reading from PTY
            self.read_task = asyncio.create_task(self._read_pty())

    async def send_status(self, status, message=""):
        """Send a status message to the client."""
        if self.websocket and self.websocket.open:
            await self.websocket.send(json.dumps({
                "type": "status",
                "status": status,
                "message": message
            }))

    async def _read_pty(self):
        """Read from PTY and send to WebSocket."""
        loop = asyncio.get_event_loop()
        print(f"Starting PTY read loop for fd={self.master_fd}", flush=True)

        while True:
            try:
                # Check if process is still alive
                if not self.is_alive():
                    print("Claude process exited", flush=True)
                    await self.send_status("session_ended", "Claude session ended")
                    break

                # Wait for data to be available (runs in thread pool)
                ready = await loop.run_in_executor(None, self._wait_for_read)
                if not ready:
                    continue

                # Read available data
                data = os.read(self.master_fd, 4096)
                if not data:
                    print("PTY EOF", flush=True)
                    await self.send_status("session_ended", "Claude session ended")
                    break

                # Send to WebSocket
                if self.websocket and self.websocket.open:
                    await self.websocket.send(data.decode("utf-8", errors="replace"))

            except OSError as e:
                print(f"PTY read OSError: {e}", flush=True)
                await self.send_status("session_ended", f"Connection lost: {e}")
                break
            except Exception as e:
                print(f"PTY read error: {e}", flush=True)
                break

        print("PTY read loop ended", flush=True)
        self.pid = None  # Mark session as dead

    def _wait_for_read(self):
        """Block until PTY has data (runs in executor). Returns True if data ready."""
        import select
        readable, _, _ = select.select([self.master_fd], [], [], 0.5)
        return len(readable) > 0

    def write(self, data: str):
        """Write input to PTY."""
        if self.master_fd:
            os.write(self.master_fd, data.encode("utf-8"))

    def resize(self, cols: int, rows: int):
        """Resize the PTY."""
        if self.master_fd:
            winsize = struct.pack("HHHH", rows, cols, 0, 0)
            fcntl.ioctl(self.master_fd, termios.TIOCSWINSZ, winsize)

    def is_alive(self) -> bool:
        """Check if Claude process is still running."""
        if self.pid:
            try:
                pid, status = os.waitpid(self.pid, os.WNOHANG)
                # pid=0 means child still running, pid>0 means exited
                if pid == 0:
                    return True
                else:
                    print(f"Claude process {self.pid} exited with status {status}", flush=True)
                    self.pid = None
                    return False
            except ChildProcessError:
                self.pid = None
                return False
        return False

    async def stop(self):
        """Stop the session (idempotent - safe to call multiple times)."""
        if self.read_task:
            self.read_task.cancel()
            try:
                await self.read_task
            except asyncio.CancelledError:
                pass
            self.read_task = None

        if self.pid:
            try:
                os.kill(self.pid, signal.SIGTERM)
                await asyncio.sleep(0.5)
                os.kill(self.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            self.pid = None

        if self.master_fd:
            try:
                os.close(self.master_fd)
            except OSError:
                pass  # Already closed
            self.master_fd = None


# Global session (single session for now)
current_session = None  # type: ClaudeSession | None


async def handle_client(websocket):
    """Handle a WebSocket client connection."""
    global current_session

    client_ip = websocket.remote_address[0]
    print(f"Client connected: {client_ip}", flush=True)

    # Wait for init message with cwd
    cwd = None
    try:
        init_msg = await asyncio.wait_for(websocket.recv(), timeout=5.0)
        if init_msg.startswith("{"):
            msg = json.loads(init_msg)
            if msg.get("type") == "init":
                cwd = msg.get("cwd")
                cols = msg.get("cols", 80)
                rows = msg.get("rows", 24)
                print(f"Init: cwd={cwd}, cols={cols}, rows={rows}", flush=True)
    except (asyncio.TimeoutError, json.JSONDecodeError) as e:
        print(f"No init message received: {e}", flush=True)

    async def send_status(status, message=""):
        await websocket.send(json.dumps({"type": "status", "status": status, "message": message}))

    async def start_new_session():
        global current_session
        await send_status("starting", "Starting Claude...")
        if current_session:
            await current_session.stop()
        current_session = ClaudeSession()
        await current_session.start(websocket, cwd=cwd)
        if cwd:
            current_session.resize(cols, rows)
        await send_status("ready", "Claude is ready")

    # Always start fresh session (session persistence removed for reliability)
    print(f"Starting new Claude session in {cwd}...", flush=True)
    await start_new_session()

    try:
        async for message in websocket:
            # Check if it's a control message (JSON)
            if message.startswith("{"):
                try:
                    msg = json.loads(message)
                    if msg.get("type") == "resize":
                        print(f"Resize: {msg['cols']}x{msg['rows']}", flush=True)
                        current_session.resize(msg["cols"], msg["rows"])
                        continue
                    elif msg.get("type") == "init":
                        # Already handled above
                        continue
                    elif msg.get("type") == "restart":
                        # User requested session restart
                        print("Restart requested", flush=True)
                        await start_new_session()
                        continue
                    elif msg.get("type") == "ping":
                        await websocket.send(json.dumps({"type": "pong"}))
                        continue
                except json.JSONDecodeError:
                    pass

            # Regular input - send to PTY
            if current_session:
                current_session.write(message)

    except websockets.exceptions.ConnectionClosed:
        print(f"Client disconnected: {client_ip}", flush=True)
    except Exception as e:
        print(f"Error: {e}", flush=True)
    finally:
        # Clean up: stop Claude session when client disconnects
        if current_session:
            print("Stopping Claude session...", flush=True)
            await current_session.stop()
            current_session = None
        print("Connection closed", flush=True)


async def main():
    """Main entry point."""
    print(f"Claude Anywhere Relay Server")
    print(f"Listening on ws://{HOST}:{PORT}")
    print(f"Connect from Obsidian plugin or test with: websocat ws://localhost:{PORT}")
    print()

    async with serve(handle_client, HOST, PORT):
        await asyncio.Future()  # Run forever


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nShutting down...")
