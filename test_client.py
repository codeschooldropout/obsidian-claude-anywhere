#!/usr/bin/env python3
"""
Simple test client for the relay server.
Run this to verify WebSocket connectivity works.
"""

import asyncio
import sys
import websockets


async def test_connection():
    uri = "ws://localhost:8765"
    print(f"Connecting to {uri}...")

    try:
        async with websockets.connect(uri) as websocket:
            print("Connected!")
            print("Type commands (or 'quit' to exit):")
            print("-" * 40)

            # Start a task to read from websocket
            async def read_output():
                try:
                    async for message in websocket:
                        print(message, end="", flush=True)
                except:
                    pass

            read_task = asyncio.create_task(read_output())

            # Read from stdin and send
            loop = asyncio.get_event_loop()
            while True:
                try:
                    line = await loop.run_in_executor(None, sys.stdin.readline)
                    if not line or line.strip() == "quit":
                        break
                    await websocket.send(line)
                except EOFError:
                    break

            read_task.cancel()

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    asyncio.run(test_connection())
