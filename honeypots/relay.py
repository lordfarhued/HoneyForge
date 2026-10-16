from __future__ import annotations

import os
import socket
import socketserver
import threading


MAX_UDP_PAYLOAD = 8192
TCP_CONNECT_TIMEOUT_SECONDS = 10


def copy_stream(source: socket.socket, destination: socket.socket) -> None:
    try:
        while True:
            chunk = source.recv(16_384)
            if not chunk:
                break
            destination.sendall(chunk)
    except OSError:
        pass
    finally:
        try:
            destination.shutdown(socket.SHUT_WR)
        except OSError:
            pass


class TCPRelayHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        source_ip, source_port = self.client_address[:2]
        family = "TCP6" if ":" in source_ip else "TCP4"
        with socket.create_connection(
            (self.server.target_host, self.server.target_port),
            timeout=TCP_CONNECT_TIMEOUT_SECONDS,
        ) as upstream:
            # The timeout above only bounds establishing the backend connection.
            # Leaving it on the socket would tear down otherwise healthy SSH
            # sessions whenever a client spends that long at a password prompt.
            upstream.settimeout(None)
            destination_ip = upstream.getpeername()[0]
            upstream.sendall(
                f"PROXY {family} {source_ip} {destination_ip} {source_port} {self.server.target_port}\r\n".encode("ascii")
            )
            outbound = threading.Thread(target=copy_stream, args=(self.request, upstream), daemon=True)
            outbound.start()
            copy_stream(upstream, self.request)
            outbound.join(timeout=2)


class UDPRelayHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        payload, public_socket = self.request
        source_ip, source_port = self.client_address[:2]
        address_info = socket.getaddrinfo(
            self.server.target_host,
            self.server.target_port,
            type=socket.SOCK_DGRAM,
        )[0]
        family, socktype, protocol, _, target = address_info
        marker = "UDP6" if family == socket.AF_INET6 else "UDP4"
        with socket.socket(family, socktype, protocol) as upstream:
            upstream.settimeout(3)
            upstream.connect(target)
            destination_ip = upstream.getpeername()[0]
            header = (
                f"PROXY {marker} {source_ip} {destination_ip} {source_port} {self.server.target_port}\r\n"
            ).encode("ascii")
            upstream.send(header + payload)
            try:
                response = upstream.recv(65_535)
            except (OSError, TimeoutError):
                return
        try:
            public_socket.sendto(response, self.client_address)
        except OSError:
            pass


class TCPRelayServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address, target_host: str, target_port: int):
        self.target_host = target_host
        self.target_port = target_port
        super().__init__(server_address, TCPRelayHandler)


class UDPRelayServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True
    daemon_threads = True
    max_packet_size = MAX_UDP_PAYLOAD + 1

    def __init__(self, server_address, target_host: str, target_port: int):
        self.target_host = target_host
        self.target_port = target_port
        super().__init__(server_address, UDPRelayHandler)


def run() -> None:
    listen_port = int(os.environ["HF_RELAY_LISTEN_PORT"])
    target_host = os.environ["HF_RELAY_TARGET_HOST"]
    target_port = int(os.environ.get("HF_RELAY_TARGET_PORT", str(listen_port)))
    relay_protocol = os.environ.get("HF_RELAY_PROTOCOL", "tcp").lower()
    if relay_protocol == "tcp":
        server_class = TCPRelayServer
    elif relay_protocol == "udp":
        server_class = UDPRelayServer
    else:
        raise ValueError("HF_RELAY_PROTOCOL must be tcp or udp")
    with server_class(("0.0.0.0", listen_port), target_host, target_port) as server:
        server.serve_forever()


if __name__ == "__main__":
    run()
