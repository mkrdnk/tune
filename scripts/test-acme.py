#!/usr/bin/env python3
"""Run real HTTP-01 issuance against a local Pebble CA, without public DNS."""
import argparse
import datetime
import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def dns_loop(sock):
    while True:
        try:
            connection, _ = sock.accept()
        except OSError:
            return
        with connection:
            connection.settimeout(2)
            incoming = connection.makefile("rb")
            prefix = incoming.read(2)
            if len(prefix) != 2:
                continue
            packet = incoming.read(struct.unpack("!H", prefix)[0])
            offset = 12
            while packet[offset]:
                offset += packet[offset] + 1
            end = offset + 5
            qtype = struct.unpack("!H", packet[offset + 1:offset + 3])[0]
            answer = b""
            if qtype == 1:
                answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 1, 4) + socket.inet_aton("127.0.0.1")
            header = packet[:2] + struct.pack("!HHHHH", 0x8180, 1, bool(answer), 0, 0)
            response = header + packet[12:end] + answer
            connection.sendall(struct.pack("!H", len(response)) + response)
            incoming.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pebble", default="pebble")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="tune-acme-") as directory:
        work = Path(directory)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.datetime.now(datetime.timezone.utc)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Tune Pebble test CA")])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=1))
                .not_valid_after(now + datetime.timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
                .sign(key, hashes.SHA256()))
        (work / "api.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (work / "api-key.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        api_port, management_port, http_port = free_port(), free_port(), free_port()
        config = {"pebble": {"listenAddress": f"127.0.0.1:{api_port}",
            "managementListenAddress": f"127.0.0.1:{management_port}",
            "certificate": str(work / "api.pem"), "privateKey": str(work / "api-key.pem"),
            "httpPort": http_port, "tlsPort": free_port(), "keyAlgorithm": "ecdsa",
            "retryAfter": {"authz": 1, "order": 1}}}
        (work / "pebble.json").write_text(json.dumps(config))
        dns = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        dns.bind(("127.0.0.1", 0))
        dns.listen(16)
        threading.Thread(target=dns_loop, args=(dns,), daemon=True).start()
        env = os.environ | {"PEBBLE_VA_NOSLEEP": "1", "PEBBLE_WFE_NONCEREJECT": "0"}
        env.pop("PEBBLE_VA_ALWAYS_VALID", None)
        with (work / "pebble.log").open("w+") as log:
            process = subprocess.Popen([args.pebble, "-config", str(work / "pebble.json"),
                "-dnsserver", f"127.0.0.1:{dns.getsockname()[1]}"], env=env, stdout=log, stderr=log)
            try:
                context = ssl.create_default_context(cafile=str(work / "api.pem"))
                deadline = time.monotonic() + 15
                while True:
                    try:
                        with urllib.request.urlopen(f"https://127.0.0.1:{management_port}/roots/0", context=context, timeout=1) as response:
                            root = response.read()
                        break
                    except (OSError, urllib.error.URLError):
                        if time.monotonic() > deadline or process.poll() is not None:
                            raise RuntimeError("Pebble did not start")
                        time.sleep(0.1)
                bundle = work / "trust.pem"
                bundle.write_bytes((work / "api.pem").read_bytes() + root)
                env.update({"SSL_CERT_FILE": str(bundle),
                    "TUNE_TEST_ACME_DIRECTORY": f"https://127.0.0.1:{api_port}/dir",
                    "TUNE_TEST_ACME_STATE": str(work / "state"),
                    "TUNE_TEST_ACME_HTTP_PORT": str(http_port),
                    "CRYSTAL_CACHE_DIR": os.environ.get("CRYSTAL_CACHE_DIR", "/tmp/tune-crystal-cache")})
                result = subprocess.run(["crystal", "spec", "spec/acme_spec.cr"], env=env)
                if result.returncode:
                    log.flush()
                    log.seek(0)
                    print(log.read())
                return result.returncode
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                dns.close()


if __name__ == "__main__":
    raise SystemExit(main())
