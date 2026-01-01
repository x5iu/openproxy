"""
Simple WebSocket echo server for testing openproxy WebSocket support.

This server echoes back any message it receives, useful for testing
the WebSocket proxy functionality.

Usage:
    python websocket_echo_server.py [--host HOST] [--port PORT] [--ssl]

Requirements:
    pip install websockets
"""

import asyncio
import argparse
import ssl
import os


try:
    import websockets
    from websockets.server import serve as ws_serve
except ImportError:
    print("Error: websockets library required. Install with: pip install websockets")
    exit(1)


async def echo_handler(websocket):
    """Handle WebSocket connections by echoing all messages."""
    client_info = f"{websocket.remote_address[0]}:{websocket.remote_address[1]}"
    print(f"[+] Client connected: {client_info}")

    try:
        async for message in websocket:
            msg_preview = str(message)[:50] + "..." if len(str(message)) > 50 else str(message)
            print(f"[<] Received from {client_info}: {msg_preview}")

            # Echo the message back
            await websocket.send(message)
            print(f"[>] Sent to {client_info}: {msg_preview}")

    except websockets.ConnectionClosed as e:
        print(f"[-] Client disconnected: {client_info} (code={e.code}, reason={e.reason})")
    except Exception as e:
        print(f"[!] Error with {client_info}: {e}")


async def main(host: str, port: int, use_ssl: bool, cert_file: str = None, key_file: str = None):
    """Start the WebSocket echo server."""
    ssl_context = None

    if use_ssl:
        if not cert_file or not key_file:
            print("Error: --ssl requires --cert and --key options")
            return

        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(cert_file, key_file)
        print(f"SSL enabled with cert: {cert_file}")

    protocol = "wss" if use_ssl else "ws"
    print(f"Starting WebSocket echo server on {protocol}://{host}:{port}")
    print("Press Ctrl+C to stop")

    async with ws_serve(echo_handler, host, port, ssl=ssl_context):
        await asyncio.Future()  # Run forever


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WebSocket Echo Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=9000, help="Port to listen on (default: 9000)")
    parser.add_argument("--ssl", action="store_true", help="Enable SSL/TLS")
    parser.add_argument("--cert", help="SSL certificate file")
    parser.add_argument("--key", help="SSL private key file")

    args = parser.parse_args()

    try:
        asyncio.run(main(args.host, args.port, args.ssl, args.cert, args.key))
    except KeyboardInterrupt:
        print("\nServer stopped")
