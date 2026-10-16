from __future__ import annotations

import base64
import socket
import time

from honeypots.common import (
    EventWriter,
    RuntimeSupervisor,
    ServiceHandle,
    ThreadedTCPServer,
    ThreadedUDPServer,
    apply_response_delay,
    logging_enabled,
    proxy_datagram,
    proxy_peer,
    start_server,
)

MAX_REQUEST = 8192
MAX_UDP_PAYLOAD = 8192


def safe_banner(value: str) -> str:
    return value.replace("\r", " ").replace("\n", " ")[:200] or "service"


class LowHandlerMixin:
    instance: dict
    service: dict
    writer: EventWriter


def build_handler(instance: dict, service: dict, writer: EventWriter):
    class LowHandler(LowHandlerMixin):
        def __init__(self, request: socket.socket, client_address, server):
            self.request = request
            self.client_address = client_address
            self.server = server
            self.handle()

        def handle(self) -> None:
            started = time.monotonic()
            source_ip, source_port = self.client_address[0], self.client_address[1]
            self.request.settimeout(3)
            try:
                source_ip, source_port = proxy_peer(self.request, source_ip, source_port)
            except (OSError, ValueError):
                return
            received = b""
            name = str(service.get("name", "tcp")).lower()
            banner = safe_banner(str(service.get("banner", "")))
            capture_connections = logging_enabled(instance, "capture_connections")
            capture_commands = logging_enabled(instance, "capture_commands")
            capture_payloads = logging_enabled(instance, "capture_payloads")
            try:
                if name == "http":
                    received = self.request.recv(MAX_REQUEST)
                    body = b"<html><body><h1>Welcome</h1></body></html>"
                    response = (
                        b"HTTP/1.1 200 OK\r\n"
                        + f"Server: {banner}\r\n".encode("utf-8")
                        + b"Content-Type: text/html; charset=utf-8\r\n"
                        + f"Content-Length: {len(body)}\r\n".encode("ascii")
                        + b"Connection: close\r\n\r\n"
                        + body
                    )
                    apply_response_delay(instance)
                    self.request.sendall(response)
                else:
                    apply_response_delay(instance)
                    self.request.sendall((banner + "\r\n").encode("utf-8"))
                    received = self.request.recv(MAX_REQUEST)
                    self.request.sendall(b"OK\r\n")
            except (OSError, TimeoutError):
                pass
            text = received.decode("utf-8", errors="replace")[:MAX_REQUEST]
            request_line = text.splitlines()[0][:1024] if text else ""
            controlled = "x-honeyforge-verification: stage3" in text.lower()
            if capture_connections or capture_commands or capture_payloads:
                data = {
                    "engine": "low",
                    "service": name,
                    "protocol": "tcp",
                    "destination_port": int(service["port"]),
                    "banner": banner,
                    "controlled_test": controlled,
                }
                if capture_connections:
                    data.update(
                        source_port=source_port,
                        bytes_received=len(received),
                        duration_ms=round((time.monotonic() - started) * 1000, 2),
                    )
                if capture_commands:
                    data["request_line"] = request_line
                if capture_payloads:
                    data["request"] = text
                writer.emit(
                    str(instance["instance_id"]),
                    "low.http_request" if name == "http" else "low.tcp_session",
                    source_ip,
                    data,
                )

    return LowHandler


def build_udp_handler(instance: dict, service: dict, writer: EventWriter):
    class LowUDPHandler(LowHandlerMixin):
        def __init__(self, request, client_address, server):
            self.request = request
            self.client_address = client_address
            self.server = server
            self.handle()

        def handle(self) -> None:
            started = time.monotonic()
            received, response_socket = self.request
            source_ip, source_port = self.client_address[:2]
            destination_ip, destination_port = response_socket.getsockname()[:2]
            try:
                received, source_ip, source_port, destination_ip, destination_port = proxy_datagram(
                    received,
                    source_ip,
                    source_port,
                    destination_ip,
                    destination_port,
                )
            except (UnicodeDecodeError, ValueError):
                return

            truncated = len(received) > MAX_UDP_PAYLOAD
            payload = received[:MAX_UDP_PAYLOAD]
            name = str(service.get("name", "udp")).lower()
            banner = safe_banner(str(service.get("banner", "")))
            capture_connections = logging_enabled(instance, "capture_connections")
            capture_commands = logging_enabled(instance, "capture_commands")
            capture_payloads = logging_enabled(instance, "capture_payloads")

            apply_response_delay(instance)
            try:
                response_socket.sendto(banner.encode("utf-8"), self.client_address)
            except OSError:
                pass

            if not (capture_connections or capture_commands or capture_payloads):
                return
            text = payload.decode("utf-8", errors="replace")
            data = {
                "engine": "low",
                "service": name,
                "protocol": "udp",
                "destination_address": destination_ip,
                "destination_port": int(destination_port),
                "banner": banner,
            }
            if capture_connections:
                data.update(
                    source_port=int(source_port),
                    bytes_received=len(received),
                    payload_truncated=truncated,
                    duration_ms=round((time.monotonic() - started) * 1000, 2),
                )
            if capture_commands:
                data["request_line"] = text.splitlines()[0][:1024] if text else ""
            if capture_payloads:
                data.update(
                    payload_base64=base64.b64encode(payload).decode("ascii"),
                    payload_encoding="base64",
                    payload_truncated=truncated,
                )
            writer.emit(
                str(instance["instance_id"]),
                "low.udp_datagram",
                source_ip,
                data,
            )

    return LowUDPHandler


def service_factory(instance: dict, service: dict, writer: EventWriter) -> ServiceHandle:
    port = int(service["port"])
    protocol = str(service.get("protocol", ""))
    if protocol == "tcp":
        server = ThreadedTCPServer(("0.0.0.0", port), build_handler(instance, service, writer))
    elif protocol == "udp":
        server = ThreadedUDPServer(("0.0.0.0", port), build_udp_handler(instance, service, writer))
    else:
        raise ValueError("unsupported low service protocol")
    return start_server(server, f"low-{protocol}-{instance['instance_id']}-{port}")


if __name__ == "__main__":
    RuntimeSupervisor(
        "low",
        "/run/honeyforge-config/config.json",
        "/var/lib/honeyforge-events",
        service_factory,
    ).run()
