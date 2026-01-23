"""
E2E test for SIGHUP config reload during active streaming requests.

This test verifies that:
1. SIGHUP config reload doesn't cause deadlock during HTTP/1.1 streaming
2. Server remains responsive to new requests after SIGHUP

Note: Config reload sends a shutdown signal that may interrupt existing
connections. This is expected behavior - the key test is that the server
doesn't deadlock and responds to new requests.

This is a regression test for the RwLock starvation fix.
"""

import concurrent.futures
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx


# Configuration
PROXY_HTTP_PORT = 19081
STREAMING_BACKEND_PORT = 19082

# Timing configuration
CHUNK_COUNT = 10
CHUNK_DELAY_MS = 500  # 500ms between chunks, total ~5s streaming duration
SIGHUP_DELAY_S = 2.0  # Send SIGHUP 2s after streaming starts
TEST_TIMEOUT_S = 15.0  # Overall test timeout
NEW_REQUEST_TIMEOUT_S = 3.0  # Timeout for verifying server responsiveness after SIGHUP

TEST_HOST = f"streaming-test.local:{PROXY_HTTP_PORT}"


def find_openproxy_binary() -> str:
    """Find the openproxy binary."""
    if "OPENPROXY_BINARY" in os.environ:
        return os.environ["OPENPROXY_BINARY"]

    candidates = [
        Path(__file__).parent.parent / "target" / "release" / "openproxy",
        Path(__file__).parent.parent / "target" / "debug" / "openproxy",
    ]

    for candidate in candidates:
        if candidate.exists():
            return str(candidate)

    raise FileNotFoundError("Could not find openproxy binary")


def create_config(config_file: str):
    """Generate a config file for the test."""
    config = f"""
http_port: {PROXY_HTTP_PORT}

providers:
  - type: forward
    host: {TEST_HOST}
    endpoint: localhost
    port: {STREAMING_BACKEND_PORT}
    tls: false
"""
    with open(config_file, "w") as f:
        f.write(config)


def start_streaming_backend() -> subprocess.Popen:
    """Start a backend server that returns slow chunked responses."""
    server_code = f'''
import time
from http.server import HTTPServer, BaseHTTPRequestHandler

class StreamingHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        try:
            if self.path == "/stream":
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()

                for i in range({CHUNK_COUNT}):
                    chunk_data = f"chunk-{{i}}-data\\n"
                    chunk = f"{{len(chunk_data):x}}\\r\\n{{chunk_data}}\\r\\n"
                    self.wfile.write(chunk.encode())
                    self.wfile.flush()
                    time.sleep({CHUNK_DELAY_MS / 1000})

                # Send final chunk
                self.wfile.write(b"0\\r\\n\\r\\n")
                self.wfile.flush()
            elif self.path == "/verify":
                body = b"OK"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
        except BrokenPipeError:
            # Client disconnected - this is expected during config reload
            pass

    def log_message(self, *args):
        pass

HTTPServer(("127.0.0.1", {STREAMING_BACKEND_PORT}), StreamingHandler).serve_forever()
'''
    return subprocess.Popen(
        [sys.executable, "-c", server_code],
        stderr=subprocess.DEVNULL,  # Suppress stderr from backend
    )


def start_openproxy(config_file: str, log_file: str) -> tuple[subprocess.Popen, "file"]:
    """Start the openproxy server with output redirected to a log file."""
    binary = find_openproxy_binary()
    log_handle = open(log_file, "w")
    proc = subprocess.Popen(
        [binary, "start", "-c", config_file],
        stdout=log_handle,
        stderr=log_handle,
    )
    return proc, log_handle


def wait_for_server(port: int, path: str = "/verify", timeout: float = 10.0) -> bool:
    """Wait for a server to be ready."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            with httpx.Client(timeout=1.0) as client:
                resp = client.get(
                    f"http://localhost:{port}{path}",
                    headers={"Host": TEST_HOST},
                )
                if resp.status_code in (200, 404):
                    return True
        except Exception:
            pass
        time.sleep(0.1)
    return False


def make_streaming_request() -> tuple[bool, str, float]:
    """
    Make a streaming request to the proxy.
    Returns (success, content, elapsed_time).
    Content includes any data received even if the stream was interrupted.
    """
    start_time = time.time()
    content = ""
    try:
        with httpx.Client(timeout=TEST_TIMEOUT_S) as client:
            with client.stream(
                "GET",
                f"http://localhost:{PROXY_HTTP_PORT}/stream",
                headers={"Host": TEST_HOST},
            ) as resp:
                if resp.status_code != 200:
                    return False, f"Status code: {resp.status_code}", time.time() - start_time

                for chunk in resp.iter_text():
                    content += chunk

                elapsed = time.time() - start_time
                return True, content, elapsed
    except Exception as e:
        # Return partial content along with error info
        elapsed = time.time() - start_time
        error_info = f"[Error: {e}]"
        if content:
            return False, content + error_info, elapsed
        return False, error_info, elapsed


def test_sighup_during_streaming():
    """Test that SIGHUP doesn't cause deadlock during streaming."""
    print(f"\n{'='*50}")
    print("Testing SIGHUP Reload During Streaming HTTP/1.1 Request")
    print("=" * 50)

    processes = []
    file_handles = []
    tmpdir = tempfile.mkdtemp()
    config_file = os.path.join(tmpdir, "config.yml")
    log_file = os.path.join(tmpdir, "proxy.log")

    try:
        # Step 1: Start streaming backend server
        print("  Starting streaming backend server...")
        backend = start_streaming_backend()
        processes.append(backend)
        time.sleep(0.5)

        # Verify backend is ready
        if not wait_for_server(STREAMING_BACKEND_PORT, "/verify", timeout=5.0):
            raise RuntimeError("Backend server did not start")
        print(f"  Backend server ready on port {STREAMING_BACKEND_PORT}")

        # Step 2: Create config and start openproxy
        print("  Starting openproxy...")
        create_config(config_file)
        proxy, log_handle = start_openproxy(config_file, log_file)
        processes.append(proxy)
        file_handles.append(log_handle)

        # Wait for proxy to be ready
        if not wait_for_server(PROXY_HTTP_PORT, "/verify", timeout=10.0):
            if proxy.poll() is not None:
                log_handle.flush()
                with open(log_file, "r") as f:
                    print(f"  Proxy log:\n{f.read()}")
            raise RuntimeError("Proxy did not start")

        proxy_pid = proxy.pid
        print(f"  Proxy started with PID: {proxy_pid}")

        # Step 3: Start streaming request in background thread
        print(f"  Starting streaming request (will take ~{CHUNK_COUNT * CHUNK_DELAY_MS / 1000}s)...")

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(make_streaming_request)

            # Step 4: Wait, then send SIGHUP
            print(f"  Waiting {SIGHUP_DELAY_S}s before sending SIGHUP...")
            time.sleep(SIGHUP_DELAY_S)

            print(f"  Sending SIGHUP to proxy (PID {proxy_pid})...")
            sighup_start = time.time()
            os.kill(proxy_pid, signal.SIGHUP)

            # Step 5: Verify server responds to new requests (this is the key test!)
            # If there's a deadlock, this request will timeout
            print("  Verifying server responds to new requests...")
            try:
                with httpx.Client(timeout=NEW_REQUEST_TIMEOUT_S) as client:
                    verify_start = time.time()
                    resp = client.get(
                        f"http://localhost:{PROXY_HTTP_PORT}/verify",
                        headers={"Host": TEST_HOST},
                    )
                    verify_elapsed = time.time() - verify_start
                    print(f"  New request completed in {verify_elapsed:.2f}s (status: {resp.status_code})")

                    if resp.status_code != 200:
                        raise AssertionError(f"Expected 200, got {resp.status_code}")

            except httpx.TimeoutException:
                raise AssertionError(
                    f"DEADLOCK DETECTED: Server did not respond within {NEW_REQUEST_TIMEOUT_S}s after SIGHUP"
                )

            sighup_elapsed = time.time() - sighup_start
            print(f"  SIGHUP handling completed in {sighup_elapsed:.2f}s")

            # Step 6: Wait for streaming request to complete
            print("  Waiting for streaming request to complete...")
            success, content, stream_elapsed = future.result(timeout=TEST_TIMEOUT_S)
            print(f"  Streaming request completed in {stream_elapsed:.2f}s")
            print(f"  Response length: {len(content)} bytes")

        # Step 7: Verify results
        # Note: Config reload sends shutdown signal that may interrupt existing connections.
        # This is expected behavior - the key test is that the server doesn't deadlock.

        # Check how many chunks were received (streaming may be interrupted)
        chunks_received = sum(1 for i in range(CHUNK_COUNT) if f"chunk-{i}-data" in content)
        print(f"  Chunks received: {chunks_received}/{CHUNK_COUNT}")

        if success:
            print(f"  Streaming completed successfully with all chunks")
        else:
            # Streaming was interrupted - this is expected during config reload
            print(f"  Streaming was interrupted (expected during config reload)")
            if chunks_received > 0:
                # Show partial content (actual data received)
                data_part = content.split("[Error:")[0] if "[Error:" in content else content
                preview = data_part[:80] + "..." if len(data_part) > 80 else data_part
                print(f"  Partial data received: {preview}")

        print(f"\n  PASSED: SIGHUP completed without deadlock!")

    finally:
        # Cleanup
        print("\nCleaning up...")
        for proc in processes:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

        for fh in file_handles:
            try:
                fh.close()
            except Exception:
                pass

        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)
        print("Cleanup complete")


def main():
    test_sighup_during_streaming()

    print("\n" + "=" * 50)
    print("SUCCESS: SIGHUP deadlock test passed!")
    print("=" * 50)


if __name__ == "__main__":
    main()
