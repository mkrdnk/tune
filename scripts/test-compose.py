#!/usr/bin/env python3
"""Test Compose HTTPS/WSS routing and Via certificate reload without public DNS/ACME.

Requires Linux Docker, Compose, and prebuilt tune:test/tune-acme:test.
"""
import http.client
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time


def run(*args, **kwargs):
    result = subprocess.run(args, text=True, capture_output=True, **kwargs)
    if result.returncode:
        raise RuntimeError(f"Command failed: {args}\n{result.stdout}\n{result.stderr}")
    return result.stdout


def main():
    root = Path(__file__).resolve().parent.parent
    with tempfile.TemporaryDirectory(prefix="tune-compose-") as directory:
        work = Path(directory)
        work.chmod(0o755)
        env = os.environ | {
            "TUNE_DOMAIN": "tune.test", "ACME_EMAIL": "test@example.com",
            "DNS_PROVIDER": "unused", "ACME_ACCEPT_TOS": "true",
            "TUNE_SUBNET": "172.30.81.0/24", "VIA_IP": "172.30.81.2",
            "TUNE_IP": "172.30.81.3",
        }
        config = json.loads(run("docker", "compose", "-f", str(root / "compose.yaml"),
                                "config", "--no-env-resolution", "--format", "json", env=env))
        project = f"tune-test-{os.getpid()}"
        config["name"] = project
        # Compose's normalized JSON includes explicit project-scoped names.
        for category in ("networks", "volumes", "configs"):
            for name, value in config[category].items():
                value["name"] = f"{project}_{name}"
        tune, via, acme = (config["services"][name] for name in ("tune", "via", "acme"))
        for service, image in ((tune, "tune:test"), (acme, "tune-acme:test")):
            service.pop("build")
            service["image"] = image
        tune["volumes"][0]["source"] = str(work)
        # No real CA process is allowed in this smoke test. Seed test certificates
        # in the same volume and retain the production health/dependency checks.
        acme.pop("env_file")
        acme["entrypoint"] = ["/bin/sh", "-c", "exec sleep infinity"]
        acme["volumes"].append({"type": "bind", "source": str(work),
                                "target": "/fixtures", "read_only": True})
        acme["healthcheck"]["interval"] = "1s"
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        via["ports"] = [{"target": 8443, "published": str(port), "host_ip": "127.0.0.1"}]
        config["configs"]["tune"]["content"] = config["configs"]["tune"]["content"].replace(
            'domain: "tune.test"', f'domain: "tune.test"\n  public_url: "https://tune.test:{port}"')
        compose_file = work / "compose.json"
        compose_file.write_text(json.dumps(config))

        def compose(*args):
            return run("docker", "compose", "-f", str(compose_file), "-p", project, *args)

        def openssl(*args):
            return run("docker", "run", "--rm", "--network", "none",
                       "--user", f"{os.getuid()}:{os.getgid()}", "-v", f"{work}:/test",
                       "-w", "/test", "--entrypoint", "openssl", "tune-acme:test", *args)

        openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                "-nodes", "-days", "7", "-subj", "/CN=Compose test CA",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-keyout", "ca.key", "-out", "ca.crt")
        (work / "extensions").write_text("subjectAltName=DNS:tune.test,DNS:*.tune.test\n")

        def certificate(serial):
            openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                    "-nodes", "-subj", "/CN=tune.test", "-keyout", "key.pem", "-out", "cert.csr")
            openssl("x509", "-req", "-in", "cert.csr", "-CA", "ca.crt", "-CAkey", "ca.key",
                    "-set_serial", str(serial), "-days", "7", "-extfile", "extensions", "-out", "cert.pem")
            compose("run", "--rm", "--no-deps", "--entrypoint", "/bin/sh", "acme", "-ec",
                    "mkdir -p /certificates/tune.test; "
                    "cat /fixtures/cert.pem /fixtures/key.pem > /certificates/tune.test/new.pem; "
                    "chown -R 0:10001 /certificates; chmod 750 /certificates /certificates/tune.test; "
                    "chmod 640 /certificates/tune.test/new.pem; "
                    "mv /certificates/tune.test/new.pem /certificates/tune.test/tls.pem")

        context = ssl.create_default_context(cafile=str(work / "ca.crt"))

        def request(host, headers=None):
            connection = http.client.HTTPSConnection(host, port, context=context, timeout=3)
            connection._create_connection = lambda *a, **kw: socket.create_connection(("127.0.0.1", port), timeout=3)
            try:
                connection.request("GET", "/payload", headers=headers or {})
                serial = connection.sock.getpeercert()["serialNumber"]
                response = connection.getresponse()
                return response.status, response.read(), serial
            finally:
                connection.close()

        handler = lambda *a, **kw: http.server.SimpleHTTPRequestHandler(*a, directory=work, **kw)
        (work / "payload").write_text("compose-tunnel-ok")
        app = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=app.serve_forever, daemon=True).start()
        client = None
        client_name = f"{project}-client"
        try:
            run("docker", "run", "--rm", "--user", f"{os.getuid()}:{os.getgid()}",
                "-v", f"{work}:/test", "--entrypoint", "tune", "tune:test",
                "keygen", "--identity", "/test/identity")
            (work / "authorized_keys").write_bytes((work / "identity.pub").read_bytes())
            (work / "authorized_keys").chmod(0o644)
            certificate(1)
            compose("up", "-d", "--wait", "--wait-timeout", "60")
            compose("exec", "-T", "via", "via", "check", "-c", "/etc/via/config.yaml")
            run(
                "docker", "create", "--rm", "--name", client_name, "--network", "host",
                "--user", f"{os.getuid()}:{os.getgid()}", "--add-host", "tune.test:127.0.0.1",
                "-v", f"{work}:/test:ro", "-e", "SSL_CERT_FILE=/test/ca.crt",
                "--entrypoint", "tune", "tune:test", str(app.server_port),
                "--server", f"https://tune.test:{port}", "--identity", "/test/identity", "--name", "smoke",
            )
            client = subprocess.Popen(["docker", "start", "--attach", client_name],
                                      stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            deadline = time.monotonic() + 30
            while True:
                response = request("smoke.tune.test")
                if response[:2] == (200, b"compose-tunnel-ok"):
                    break
                assert time.monotonic() < deadline and client.poll() is None, response
                time.sleep(0.2)
            assert response[2] == "01", response
            # Via must overwrite attacker-provided forwarded hosts.
            assert request("smoke.tune.test", {"X-Forwarded-Host": "evil.invalid"})[0] == 200
            assert request("missing.tune.test")[0] == 404
            certificate(2)
            deadline = time.monotonic() + 15
            while request("smoke.tune.test")[2] != "02":
                assert time.monotonic() < deadline, "Via did not reload the certificate"
                time.sleep(0.2)
            assert request("smoke.tune.test")[:2] == (200, b"compose-tunnel-ok")
            assert client.poll() is None, "renewal disconnected the WSS client"
            print("Compose smoke test passed: private WSS, HTTPS routing, forwarded Host, TLS reload")
        except BaseException:
            print(compose("logs", "--no-color"))
            if client is not None and client.poll() is not None:
                print(client.stdout.read())
            raise
        finally:
            if client is not None:
                subprocess.run(["docker", "stop", "-t", "5", client_name], capture_output=True)
                try:
                    client.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    client.kill()
                    client.communicate()
            compose("down", "-v", "--remove-orphans")
            app.shutdown()
            app.server_close()


if __name__ == "__main__":
    main()
