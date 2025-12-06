#!/usr/bin/env python3
"""
End-to-end tests for WebSocket proxy support.

These tests verify that openproxy correctly proxies WebSocket connections
for both HTTP and HTTPS.

Requirements:
- websockets library: pip install websockets
- A WebSocket echo server running on the configured endpoint
"""

import asyncio
import os
import ssl
import json
from typing import Optional

# Try to import websockets, skip tests if not available
try:
    import websockets
    from websockets.client import connect as ws_connect
    WEBSOCKETS_AVAILABLE = True
except ImportError:
    WEBSOCKETS_AVAILABLE = False
    print("Warning: websockets library not installed. WebSocket tests will be skipped.")
    print("Install with: pip install websockets")


def get_test_config():
    """Get test configuration from environment variables."""
    return {
        "ws_url": os.environ.get("WS_URL", "ws://localhost:8080"),
        "wss_url": os.environ.get("WSS_URL", "wss://localhost:443"),
        "ssl_cert": os.environ.get("SSL_CERT_FILE"),
        "api_key": os.environ.get("OPENAI_API_KEY", "test-key"),
    }


async def test_websocket_echo(url: str, ssl_context: Optional[ssl.SSLContext] = None):
    """
    Test basic WebSocket echo functionality through the proxy.

    This test:
    1. Connects to a WebSocket endpoint through the proxy
    2. Sends a message
    3. Verifies the echo response
    4. Closes the connection gracefully
    """
    print(f"\n{'='*50}")
    print(f"Testing WebSocket echo: {url}")
    print('='*50)

    config = get_test_config()

    # Add authorization header
    extra_headers = {
        "Authorization": f"Bearer {config['api_key']}",
    }

    try:
        async with ws_connect(
            url,
            additional_headers=extra_headers,
            ssl=ssl_context,
            close_timeout=5,
        ) as websocket:
            # Send a test message
            test_message = "Hello, WebSocket!"
            print(f"  Sending: {test_message}")
            await websocket.send(test_message)

            # Receive the response
            response = await asyncio.wait_for(websocket.recv(), timeout=10)
            print(f"  Received: {response}")

            # Verify echo
            assert response == test_message, f"Expected echo, got: {response}"

            print("  WebSocket echo test passed!")
            return True

    except Exception as e:
        print(f"  WebSocket test failed: {e}")
        return False


async def test_websocket_multiple_messages(url: str, ssl_context: Optional[ssl.SSLContext] = None):
    """
    Test multiple message exchanges over a single WebSocket connection.
    """
    print(f"\n{'='*50}")
    print(f"Testing WebSocket multiple messages: {url}")
    print('='*50)

    config = get_test_config()

    extra_headers = {
        "Authorization": f"Bearer {config['api_key']}",
    }

    try:
        async with ws_connect(
            url,
            additional_headers=extra_headers,
            ssl=ssl_context,
            close_timeout=5,
        ) as websocket:
            messages = ["Message 1", "Message 2", "Message 3", "Final message"]

            for i, msg in enumerate(messages):
                print(f"  [{i+1}/{len(messages)}] Sending: {msg}")
                await websocket.send(msg)

                response = await asyncio.wait_for(websocket.recv(), timeout=10)
                print(f"  [{i+1}/{len(messages)}] Received: {response}")

                assert response == msg, f"Expected {msg}, got: {response}"

            print("  Multiple messages test passed!")
            return True

    except Exception as e:
        print(f"  Multiple messages test failed: {e}")
        return False


async def test_websocket_binary_data(url: str, ssl_context: Optional[ssl.SSLContext] = None):
    """
    Test binary data transmission over WebSocket.
    """
    print(f"\n{'='*50}")
    print(f"Testing WebSocket binary data: {url}")
    print('='*50)

    config = get_test_config()

    extra_headers = {
        "Authorization": f"Bearer {config['api_key']}",
    }

    try:
        async with ws_connect(
            url,
            additional_headers=extra_headers,
            ssl=ssl_context,
            close_timeout=5,
        ) as websocket:
            # Send binary data
            binary_data = bytes(range(256))
            print(f"  Sending {len(binary_data)} bytes of binary data")
            await websocket.send(binary_data)

            response = await asyncio.wait_for(websocket.recv(), timeout=10)
            print(f"  Received {len(response)} bytes")

            assert response == binary_data, "Binary data mismatch"

            print("  Binary data test passed!")
            return True

    except Exception as e:
        print(f"  Binary data test failed: {e}")
        return False


async def test_websocket_json_messages(url: str, ssl_context: Optional[ssl.SSLContext] = None):
    """
    Test JSON message exchange over WebSocket (common use case for APIs).
    """
    print(f"\n{'='*50}")
    print(f"Testing WebSocket JSON messages: {url}")
    print('='*50)

    config = get_test_config()

    extra_headers = {
        "Authorization": f"Bearer {config['api_key']}",
    }

    try:
        async with ws_connect(
            url,
            additional_headers=extra_headers,
            ssl=ssl_context,
            close_timeout=5,
        ) as websocket:
            # Send JSON messages
            json_messages = [
                {"type": "request", "id": 1, "data": {"query": "test"}},
                {"type": "request", "id": 2, "data": {"model": "gpt-4", "stream": True}},
            ]

            for msg in json_messages:
                json_str = json.dumps(msg)
                print(f"  Sending: {json_str[:50]}...")
                await websocket.send(json_str)

                response = await asyncio.wait_for(websocket.recv(), timeout=10)
                response_json = json.loads(response)
                print(f"  Received: {response[:50]}...")

                assert response_json == msg, f"JSON mismatch"

            print("  JSON messages test passed!")
            return True

    except Exception as e:
        print(f"  JSON messages test failed: {e}")
        return False


async def test_websocket_large_message(url: str, ssl_context: Optional[ssl.SSLContext] = None):
    """
    Test large message handling over WebSocket.
    """
    print(f"\n{'='*50}")
    print(f"Testing WebSocket large message: {url}")
    print('='*50)

    config = get_test_config()

    extra_headers = {
        "Authorization": f"Bearer {config['api_key']}",
    }

    try:
        async with ws_connect(
            url,
            additional_headers=extra_headers,
            ssl=ssl_context,
            close_timeout=10,
            max_size=10 * 1024 * 1024,  # 10MB max
        ) as websocket:
            # Send a large message (64KB)
            large_message = "x" * (64 * 1024)
            print(f"  Sending {len(large_message)} bytes")
            await websocket.send(large_message)

            response = await asyncio.wait_for(websocket.recv(), timeout=30)
            print(f"  Received {len(response)} bytes")

            assert response == large_message, "Large message mismatch"

            print("  Large message test passed!")
            return True

    except Exception as e:
        print(f"  Large message test failed: {e}")
        return False


async def test_websocket_connection_close(url: str, ssl_context: Optional[ssl.SSLContext] = None):
    """
    Test graceful WebSocket connection close.
    """
    print(f"\n{'='*50}")
    print(f"Testing WebSocket connection close: {url}")
    print('='*50)

    config = get_test_config()

    extra_headers = {
        "Authorization": f"Bearer {config['api_key']}",
    }

    try:
        websocket = await ws_connect(
            url,
            additional_headers=extra_headers,
            ssl=ssl_context,
            close_timeout=5,
        )

        # Send a message
        await websocket.send("test")
        await websocket.recv()

        # Close gracefully
        print("  Closing connection gracefully...")
        await websocket.close(code=1000, reason="Test complete")

        print(f"  Close code: {websocket.close_code}")
        print(f"  Close reason: {websocket.close_reason}")

        print("  Connection close test passed!")
        return True

    except Exception as e:
        print(f"  Connection close test failed: {e}")
        return False


async def test_websocket_subprotocol(url: str, ssl_context: Optional[ssl.SSLContext] = None):
    """
    Test WebSocket subprotocol negotiation.
    """
    print(f"\n{'='*50}")
    print(f"Testing WebSocket subprotocol: {url}")
    print('='*50)

    config = get_test_config()

    extra_headers = {
        "Authorization": f"Bearer {config['api_key']}",
    }

    try:
        async with ws_connect(
            url,
            additional_headers=extra_headers,
            ssl=ssl_context,
            close_timeout=5,
            subprotocols=["chat", "superchat"],
        ) as websocket:
            print(f"  Negotiated subprotocol: {websocket.subprotocol}")

            # Send and receive to verify connection works
            await websocket.send("test")
            await websocket.recv()

            print("  Subprotocol test passed!")
            return True

    except Exception as e:
        print(f"  Subprotocol test failed: {e}")
        return False


async def run_tests():
    """Run all WebSocket tests."""
    if not WEBSOCKETS_AVAILABLE:
        print("\nSkipping WebSocket tests - websockets library not available")
        return

    config = get_test_config()

    # Create SSL context for HTTPS tests
    ssl_context = None
    if config["ssl_cert"]:
        ssl_context = ssl.create_default_context()
        ssl_context.load_verify_locations(config["ssl_cert"])

    results = []

    # Test HTTP WebSocket (ws://)
    if config.get("ws_url"):
        print("\n" + "="*60)
        print("TESTING HTTP WEBSOCKET (ws://)")
        print("="*60)

        results.append(("WS Echo", await test_websocket_echo(config["ws_url"])))
        results.append(("WS Multiple Messages", await test_websocket_multiple_messages(config["ws_url"])))
        results.append(("WS Binary", await test_websocket_binary_data(config["ws_url"])))
        results.append(("WS JSON", await test_websocket_json_messages(config["ws_url"])))
        results.append(("WS Large Message", await test_websocket_large_message(config["ws_url"])))
        results.append(("WS Close", await test_websocket_connection_close(config["ws_url"])))

    # Test HTTPS WebSocket (wss://)
    if config.get("wss_url") and ssl_context:
        print("\n" + "="*60)
        print("TESTING HTTPS WEBSOCKET (wss://)")
        print("="*60)

        results.append(("WSS Echo", await test_websocket_echo(config["wss_url"], ssl_context)))
        results.append(("WSS Multiple Messages", await test_websocket_multiple_messages(config["wss_url"], ssl_context)))
        results.append(("WSS Binary", await test_websocket_binary_data(config["wss_url"], ssl_context)))
        results.append(("WSS JSON", await test_websocket_json_messages(config["wss_url"], ssl_context)))
        results.append(("WSS Large Message", await test_websocket_large_message(config["wss_url"], ssl_context)))
        results.append(("WSS Close", await test_websocket_connection_close(config["wss_url"], ssl_context)))

    # Print summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)

    passed = sum(1 for _, result in results if result)
    failed = len(results) - passed

    for name, result in results:
        status = "PASSED" if result else "FAILED"
        print(f"  {name}: {status}")

    print(f"\nTotal: {passed} passed, {failed} failed")

    if failed > 0:
        print("\nSome WebSocket tests failed!")
        exit(1)
    else:
        print("\nAll WebSocket tests passed!")


if __name__ == "__main__":
    # Check if we should skip tests
    if os.environ.get("SKIP_WEBSOCKET_TESTS"):
        print("WebSocket tests skipped (SKIP_WEBSOCKET_TESTS is set)")
        exit(0)

    # Run tests
    asyncio.run(run_tests())
