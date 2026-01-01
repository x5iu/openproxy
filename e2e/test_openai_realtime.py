"""
End-to-end test for WebSocket proxy using OpenAI Realtime API.

This test verifies that openproxy correctly proxies WebSocket connections
to OpenAI's Realtime API (wss://api.openai.com/v1/realtime).

Requirements:
- websocket-client library: pip install websocket-client
- OPENAI_API_KEY environment variable set with a valid API key
- openproxy running and configured to proxy to api.openai.com

Usage:
    # Direct connection to OpenAI (baseline test)
    python test_openai_realtime.py --direct

    # Through openproxy (proxy test)
    PROXY_HOST=localhost PROXY_PORT=443 python test_openai_realtime.py

    # With custom SSL cert for proxy
    SSL_CERT_FILE=/path/to/cert.pem python test_openai_realtime.py
"""

import os
import sys
import json
import time
import ssl
import argparse
import threading
from typing import Optional, List, Dict, Any

try:
    import websocket
except ImportError:
    print("Error: websocket-client library required.")
    print("Install with: pip install websocket-client")
    sys.exit(1)


class OpenAIRealtimeTest:
    """Test client for OpenAI Realtime API via WebSocket."""

    def __init__(
        self,
        api_key: str,
        proxy_host: Optional[str] = None,
        proxy_port: Optional[int] = None,
        ssl_cert: Optional[str] = None,
        model: str = "gpt-4o-realtime-preview-2024-12-17",
        timeout: int = 30,
    ):
        self.api_key = api_key
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.ssl_cert = ssl_cert
        self.model = model
        self.timeout = timeout

        self.ws: Optional[websocket.WebSocketApp] = None
        self.connected = False
        self.session_created = False
        self.response_received = False
        self.error: Optional[str] = None
        self.messages: List[Dict[str, Any]] = []
        self.done_event = threading.Event()

    def get_url(self) -> str:
        """Get the WebSocket URL."""
        if self.proxy_host:
            # Connect through proxy
            # The proxy will rewrite the Host header
            return f"wss://{self.proxy_host}:{self.proxy_port}/v1/realtime?model={self.model}"
        else:
            # Direct connection to OpenAI
            return f"wss://api.openai.com/v1/realtime?model={self.model}"

    def get_headers(self) -> List[str]:
        """Get the WebSocket headers."""
        headers = [
            f"Authorization: Bearer {self.api_key}",
            "OpenAI-Beta: realtime=v1",
        ]
        if self.proxy_host:
            # Add Host header for proxy to route correctly
            headers.append("Host: api.openai.com")
        return headers

    def on_open(self, ws):
        """Handle WebSocket connection opened."""
        print("[+] Connected to OpenAI Realtime API")
        self.connected = True

        # Send a simple text message to test the connection
        # Create a conversation item with text input
        event = {
            "type": "conversation.item.create",
            "item": {
                "type": "message",
                "role": "user",
                "content": [
                    {
                        "type": "input_text",
                        "text": "Say 'Hello, WebSocket test successful!' and nothing else."
                    }
                ]
            }
        }
        print(f"[>] Sending: {event['type']}")
        ws.send(json.dumps(event))

        # Request a response
        response_event = {
            "type": "response.create",
            "response": {
                "modalities": ["text"],
                "instructions": "Respond with exactly: Hello, WebSocket test successful!"
            }
        }
        print(f"[>] Sending: {response_event['type']}")
        ws.send(json.dumps(response_event))

    def on_message(self, ws, message):
        """Handle received WebSocket message."""
        try:
            data = json.loads(message)
            event_type = data.get("type", "unknown")
            self.messages.append(data)

            print(f"[<] Received: {event_type}")

            # Check for session created
            if event_type == "session.created":
                self.session_created = True
                print(f"    Session ID: {data.get('session', {}).get('id', 'unknown')}")

            # Check for response text
            elif event_type == "response.text.delta":
                delta = data.get("delta", "")
                print(f"    Text delta: {delta}")

            elif event_type == "response.text.done":
                text = data.get("text", "")
                print(f"    Text complete: {text}")
                self.response_received = True

            elif event_type == "response.done":
                print("[+] Response complete")
                self.done_event.set()

            elif event_type == "error":
                error_data = data.get("error", {})
                self.error = f"{error_data.get('type', 'unknown')}: {error_data.get('message', 'unknown error')}"
                print(f"[!] Error: {self.error}")
                self.done_event.set()

        except json.JSONDecodeError as e:
            print(f"[!] Failed to parse message: {e}")

    def on_error(self, ws, error):
        """Handle WebSocket error."""
        self.error = str(error)
        print(f"[!] WebSocket error: {error}")
        self.done_event.set()

    def on_close(self, ws, close_status_code, close_msg):
        """Handle WebSocket connection closed."""
        print(f"[-] Connection closed (code={close_status_code}, msg={close_msg})")
        self.done_event.set()

    def run(self) -> bool:
        """Run the test and return True if successful."""
        url = self.get_url()
        headers = self.get_headers()

        print(f"\n{'='*60}")
        print("OpenAI Realtime API WebSocket Test")
        print('='*60)
        print(f"URL: {url}")
        print(f"Proxy: {self.proxy_host}:{self.proxy_port}" if self.proxy_host else "Proxy: None (direct)")
        print(f"Model: {self.model}")
        print('='*60)

        # Configure SSL
        sslopt = {}
        if self.ssl_cert:
            sslopt["ca_certs"] = self.ssl_cert
        else:
            # For testing with self-signed certs, you might need:
            # sslopt["cert_reqs"] = ssl.CERT_NONE

            pass

        # Create WebSocket connection
        self.ws = websocket.WebSocketApp(
            url,
            header=headers,
            on_open=self.on_open,
            on_message=self.on_message,
            on_error=self.on_error,
            on_close=self.on_close,
        )

        # Run in a separate thread
        ws_thread = threading.Thread(
            target=lambda: self.ws.run_forever(sslopt=sslopt if sslopt else None)
        )
        ws_thread.daemon = True
        ws_thread.start()

        # Wait for completion or timeout
        completed = self.done_event.wait(timeout=self.timeout)

        # Close the connection
        if self.ws:
            self.ws.close()

        # Evaluate results
        print(f"\n{'='*60}")
        print("Test Results")
        print('='*60)

        success = True

        if not completed:
            print("[FAIL] Test timed out")
            success = False
        elif self.error:
            print(f"[FAIL] Error occurred: {self.error}")
            success = False
        elif not self.connected:
            print("[FAIL] Failed to connect")
            success = False
        elif not self.session_created:
            print("[FAIL] Session was not created")
            success = False
        else:
            print("[PASS] Connected successfully")
            print("[PASS] Session created")
            if self.response_received:
                print("[PASS] Response received")
            else:
                print("[WARN] No text response received (may be expected for some models)")

        print(f"\nTotal messages received: {len(self.messages)}")

        return success


def main():
    parser = argparse.ArgumentParser(
        description="Test WebSocket proxy with OpenAI Realtime API"
    )
    parser.add_argument(
        "--direct",
        action="store_true",
        help="Connect directly to OpenAI (skip proxy)"
    )
    parser.add_argument(
        "--proxy-host",
        default=os.environ.get("PROXY_HOST"),
        help="Proxy hostname (default: PROXY_HOST env var)"
    )
    parser.add_argument(
        "--proxy-port",
        type=int,
        default=int(os.environ.get("PROXY_PORT", "443")),
        help="Proxy port (default: PROXY_PORT env var or 443)"
    )
    parser.add_argument(
        "--ssl-cert",
        default=os.environ.get("SSL_CERT_FILE"),
        help="SSL certificate file for proxy (default: SSL_CERT_FILE env var)"
    )
    parser.add_argument(
        "--model",
        default="gpt-4o-realtime-preview-2024-12-17",
        help="Model to use (default: gpt-4o-realtime-preview-2024-12-17)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Test timeout in seconds (default: 30)"
    )

    args = parser.parse_args()

    # Get API key
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("Error: OPENAI_API_KEY environment variable not set")
        sys.exit(1)

    # Determine proxy settings
    proxy_host = None
    proxy_port = None
    if not args.direct:
        proxy_host = args.proxy_host
        proxy_port = args.proxy_port
        if not proxy_host:
            print("Warning: No proxy host specified, connecting directly")
            print("Use --proxy-host or set PROXY_HOST environment variable")

    # Run test
    test = OpenAIRealtimeTest(
        api_key=api_key,
        proxy_host=proxy_host,
        proxy_port=proxy_port,
        ssl_cert=args.ssl_cert,
        model=args.model,
        timeout=args.timeout,
    )

    success = test.run()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
