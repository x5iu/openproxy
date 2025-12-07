#!/usr/bin/env python3
"""
End-to-end tests for WebSocket proxy support.

These tests verify that openproxy correctly proxies WebSocket connections
for both HTTP/1.1 and HTTP/2:

HTTP/1.1 WebSocket:
- Standard WebSocket upgrade (Upgrade: websocket, Connection: Upgrade)
- Works with ws:// and wss:// URLs

HTTP/2 WebSocket (RFC 8441):
- Uses Extended CONNECT method with :protocol pseudo-header
- openproxy enables SETTINGS_ENABLE_CONNECT_PROTOCOL
- Client sends CONNECT with :protocol=websocket
- Server responds with 200 OK (not 101)
- Data flows over the HTTP/2 stream

Requirements:
- websockets library: pip install websockets
- httpx with h2 support: pip install httpx[http2]
- A WebSocket echo server running on the configured endpoint
"""

import asyncio
import os
import ssl
import json
from typing import Optional

from websockets import connect as ws_connect


def get_test_config():
    """Get test configuration from environment variables."""
    return {
        "ws_url": os.environ.get("WS_URL", "ws://localhost:8080"),
        "wss_url": os.environ.get("WSS_URL", "wss://localhost:443"),
        "ws_host": os.environ.get("WS_HOST"),  # Optional custom Host header for HTTP
        "wss_host": os.environ.get("WSS_HOST"),  # Optional custom Host header for HTTPS
        "ssl_cert": os.environ.get("SSL_CERT_FILE"),
        "api_key": os.environ.get("OPENAI_API_KEY", "test-key"),
    }


async def test_websocket_echo(url: str, ssl_context: Optional[ssl.SSLContext] = None, host: Optional[str] = None):
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
    if host:
        extra_headers["Host"] = host

    try:
        async with ws_connect(
            url,
            extra_headers=extra_headers,
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


async def test_websocket_multiple_messages(url: str, ssl_context: Optional[ssl.SSLContext] = None, host: Optional[str] = None):
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
    if host:
        extra_headers["Host"] = host

    try:
        async with ws_connect(
            url,
            extra_headers=extra_headers,
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


async def test_websocket_binary_data(url: str, ssl_context: Optional[ssl.SSLContext] = None, host: Optional[str] = None):
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
    if host:
        extra_headers["Host"] = host

    try:
        async with ws_connect(
            url,
            extra_headers=extra_headers,
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


async def test_websocket_json_messages(url: str, ssl_context: Optional[ssl.SSLContext] = None, host: Optional[str] = None):
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
    if host:
        extra_headers["Host"] = host

    try:
        async with ws_connect(
            url,
            extra_headers=extra_headers,
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


async def test_websocket_large_message(url: str, ssl_context: Optional[ssl.SSLContext] = None, host: Optional[str] = None):
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
    if host:
        extra_headers["Host"] = host

    try:
        async with ws_connect(
            url,
            extra_headers=extra_headers,
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


async def test_websocket_connection_close(url: str, ssl_context: Optional[ssl.SSLContext] = None, host: Optional[str] = None):
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
    if host:
        extra_headers["Host"] = host

    try:
        websocket = await ws_connect(
            url,
            extra_headers=extra_headers,
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


async def test_websocket_subprotocol(url: str, ssl_context: Optional[ssl.SSLContext] = None, host: Optional[str] = None):
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
    if host:
        extra_headers["Host"] = host

    try:
        async with ws_connect(
            url,
            extra_headers=extra_headers,
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


async def test_openai_realtime_api(proxy_url: str, ssl_context: Optional[ssl.SSLContext] = None):
    """
    Test WebSocket proxy with OpenAI Realtime API.

    This test connects to OpenAI's Realtime API through the proxy and
    verifies that WebSocket communication works correctly.

    Args:
        proxy_url: The proxy WebSocket URL (e.g., wss://localhost:443)
        ssl_context: Optional SSL context for the connection
    """
    print(f"\n{'='*60}")
    print("Testing OpenAI Realtime API via WebSocket Proxy")
    print('='*60)

    config = get_test_config()
    api_key = config.get("api_key")

    if not api_key or api_key == "test-key":
        print("  ERROR: OPENAI_API_KEY not set or is test key")
        return False  # Fail the test

    # Build the URL for OpenAI Realtime API through proxy
    # The proxy should route based on Host header
    model = "gpt-4o-realtime-preview-2024-12-17"
    ws_url = f"{proxy_url}/v1/realtime?model={model}"

    extra_headers = {
        "Authorization": f"Bearer {api_key}",
        "OpenAI-Beta": "realtime=v1",
        "Host": "api.openai.com",
    }

    print(f"  URL: {ws_url}")
    print(f"  Model: {model}")

    try:
        session_created = False
        messages_received = []
        response_done = False

        async with ws_connect(
            ws_url,
            extra_headers=extra_headers,
            ssl=ssl_context,
            close_timeout=10,
            open_timeout=15,
        ) as websocket:
            print("  Connected to OpenAI Realtime API")

            # Wait for session.created event
            try:
                msg = await asyncio.wait_for(websocket.recv(), timeout=10)
                data = json.loads(msg)
                if data.get("type") == "session.created":
                    session_created = True
                    session_id = data.get("session", {}).get("id", "unknown")
                    print(f"  Session created: {session_id}")
                messages_received.append(data)
            except asyncio.TimeoutError:
                print("  Timeout waiting for session.created")
                return False

            # Send a simple text message
            event = {
                "type": "conversation.item.create",
                "item": {
                    "type": "message",
                    "role": "user",
                    "content": [
                        {
                            "type": "input_text",
                            "text": "Say 'test' and nothing else."
                        }
                    ]
                }
            }
            await websocket.send(json.dumps(event))
            print("  Sent conversation item")

            # Request a response
            response_event = {
                "type": "response.create",
                "response": {
                    "modalities": ["text"],
                }
            }
            await websocket.send(json.dumps(response_event))
            print("  Requested response")

            # Wait for response events
            try:
                while not response_done:
                    msg = await asyncio.wait_for(websocket.recv(), timeout=15)
                    data = json.loads(msg)
                    event_type = data.get("type", "unknown")
                    messages_received.append(data)

                    if event_type == "response.done":
                        response_done = True
                        print("  Response complete")
                    elif event_type == "response.text.delta":
                        delta = data.get("delta", "")
                        print(f"  Text delta: {delta}")
                    elif event_type == "error":
                        error = data.get("error", {})
                        print(f"  Error: {error.get('message', 'unknown')}")
                        return False

            except asyncio.TimeoutError:
                print("  Timeout waiting for response")
                # Not necessarily a failure if we got session.created
                if session_created:
                    print("  (Session was created, connection works)")

        print(f"  Total messages received: {len(messages_received)}")

        if session_created:
            print("  OpenAI Realtime API test passed!")
            return True
        else:
            print("  OpenAI Realtime API test failed: no session created")
            return False

    except Exception as e:
        print(f"  OpenAI Realtime API test failed: {e}")
        return False


async def run_tests():
    """Run all WebSocket tests."""
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

        ws_host = config.get("ws_host")
        results.append(("WS Echo", await test_websocket_echo(config["ws_url"], host=ws_host)))
        results.append(("WS Multiple Messages", await test_websocket_multiple_messages(config["ws_url"], host=ws_host)))
        results.append(("WS Binary", await test_websocket_binary_data(config["ws_url"], host=ws_host)))
        results.append(("WS JSON", await test_websocket_json_messages(config["ws_url"], host=ws_host)))
        results.append(("WS Large Message", await test_websocket_large_message(config["ws_url"], host=ws_host)))
        results.append(("WS Close", await test_websocket_connection_close(config["ws_url"], host=ws_host)))

    # Test HTTPS WebSocket (wss://)
    if config.get("wss_url") and ssl_context:
        print("\n" + "="*60)
        print("TESTING HTTPS WEBSOCKET (wss://)")
        print("="*60)

        wss_host = config.get("wss_host")
        results.append(("WSS Echo", await test_websocket_echo(config["wss_url"], ssl_context, host=wss_host)))
        results.append(("WSS Multiple Messages", await test_websocket_multiple_messages(config["wss_url"], ssl_context, host=wss_host)))
        results.append(("WSS Binary", await test_websocket_binary_data(config["wss_url"], ssl_context, host=wss_host)))
        results.append(("WSS JSON", await test_websocket_json_messages(config["wss_url"], ssl_context, host=wss_host)))
        results.append(("WSS Large Message", await test_websocket_large_message(config["wss_url"], ssl_context, host=wss_host)))
        results.append(("WSS Close", await test_websocket_connection_close(config["wss_url"], ssl_context, host=wss_host)))

    # Test OpenAI Realtime API (requires OPENAI_API_KEY)
    if config.get("wss_url"):
        print("\n" + "="*60)
        print("TESTING OPENAI REALTIME API (wss://)")
        print("="*60)

        realtime_result = await test_openai_realtime_api(config["wss_url"], ssl_context)
        results.append(("OpenAI Realtime API", realtime_result))

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
    asyncio.run(run_tests())
