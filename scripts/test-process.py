#!/usr/bin/env python3
"""Exercise the built CLIs, HTTP forwarding and Unix signal lifecycle."""
import http.client
import http.server
import os
from pathlib import Path
import queue
import signal
import socket
import subprocess
import tempfile
import threading
import time
from urllib.parse import urlparse


class Application(http.server.BaseHTTPRequestHandler):
    slow_started = threading.Event()

    def do_GET(self):
        self.slow_started.set()
        time.sleep(0.5)
        self.send_response(200)
        self.send_header("Content-Length", "7")
        self.end_headers()
        self.wfile.write(b"drained")

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        self.send_response(201)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def wait_listener(port, process):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError("server exited before listening")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.05)
    raise AssertionError("server did not listen")


def main():
    root = Path(__file__).resolve().parent.parent
    client_bin, server_bin = root / "bin/tune", root / "bin/tune-server"
    assert subprocess.run([client_bin, "--version"], capture_output=True).returncode == 0
    assert subprocess.run([server_bin, "--help"], capture_output=True).returncode == 0
    with tempfile.TemporaryDirectory(prefix="tune-process-") as directory:
        work = Path(directory)
        identity = work / "identity"
        subprocess.run([client_bin, "keygen", "--identity", identity], check=True, capture_output=True)
        original = identity.read_bytes()
        public_key = Path(str(identity) + ".pub").read_text()
        assert subprocess.run([client_bin, "keygen", "--identity", identity], capture_output=True).returncode != 0
        assert identity.read_bytes() == original
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        config = work / "server.yml"
        config.write_text(f'''server:
  bind: "127.0.0.1"
  domain: "localhost"
  public_url: "http://localhost:{port}"
  insecure_local: true
auth:
  mode: private
  authorized_keys: "{identity}.pub"
''')
        application = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Application)
        threading.Thread(target=application.serve_forever, daemon=True).start()
        processes = []
        with (work / "server.log").open("w+") as server_log, (work / "client.log").open("w+") as client_log:
            try:
                server = subprocess.Popen([server_bin, "start", str(port), "--config", config], stdout=server_log, stderr=server_log)
                processes.append(server)
                wait_listener(port, server)
                client = subprocess.Popen([client_bin, str(application.server_port), "--server", f"http://localhost:{port}",
                    "--identity", identity, "--name", "process-test", "--insecure-local"], stdout=subprocess.PIPE, stderr=client_log, text=True)
                processes.append(client)
                addresses = queue.Queue()
                def read_output():
                    for line in client.stdout:
                        if line.startswith("Public:"):
                            addresses.put(line.split(None, 1)[1].strip())
                threading.Thread(target=read_output, daemon=True).start()
                url = addresses.get(timeout=5)
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("POST", "/echo?x=1", b'{"ok":true}', {"Host": urlparse(url).hostname, "Content-Type": "application/json"})
                response = connection.getresponse()
                assert response.status == 201 and response.read() == b'{"ok":true}'
                connection.close()
                Path(str(identity) + ".pub").write_text("")
                server.send_signal(signal.SIGHUP)
                assert client.wait(timeout=5) != 0, "revoked client must fail reauthentication"
                assert server.poll() is None, "revocation must not kill the server"
                Path(str(identity) + ".pub").write_text(public_key)
                server.send_signal(signal.SIGHUP)
                time.sleep(0.1)
                client = subprocess.Popen([client_bin, str(application.server_port), "--server", f"http://localhost:{port}",
                    "--identity", identity, "--name", "process-test", "--insecure-local"], stdout=subprocess.PIPE, stderr=client_log, text=True)
                processes.append(client)
                threading.Thread(target=read_output, daemon=True).start()
                second_url = addresses.get(timeout=5)
                drained = queue.Queue()
                def slow_request():
                    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                    try:
                        connection.request("GET", "/slow", headers={"Host": urlparse(second_url).hostname})
                        drained.put(connection.getresponse().read())
                    finally:
                        connection.close()
                threading.Thread(target=slow_request, daemon=True).start()
                assert Application.slow_started.wait(timeout=5)
                server.send_signal(signal.SIGTERM)
                assert drained.get(timeout=5) == b"drained", "SIGTERM must allow active responses to finish"
                assert server.wait(timeout=5) == 0
                client.send_signal(signal.SIGINT)
                assert client.wait(timeout=5) == 0
                print("Process smoke test passed: keygen, private tunnel, SIGHUP revocation, SIGINT, SIGTERM")
            except BaseException:
                for log in (server_log, client_log):
                    log.flush()
                    log.seek(0)
                    print(log.read())
                raise
            finally:
                for process in reversed(processes):
                    if process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait()
                application.shutdown()
                application.server_close()


if __name__ == "__main__":
    main()
