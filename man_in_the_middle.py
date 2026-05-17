from argparse import ArgumentParser
import hashlib
import socket
import threading

from cli_interface import MitmCli

PLAIN_PREFIX = b"plain:"


class TrafficInspector:
    @staticmethod
    def inspect(data, direction):
        sender = "klienti" if direction == "client -> server" else "serveri"
        item = "Mesazh i kapur" if direction == "client -> server" else "Pergjigje e kapur"

        if data.startswith(PLAIN_PREFIX):
            return "warning", f"{item} nga {sender}: {TrafficInspector.decode(data[len(PLAIN_PREFIX):])}"

        if data.startswith(b"-----BEGIN PUBLIC KEY-----"):
            return "info", f"Public key i kapur nga {sender}: {TrafficInspector.public_key_summary(data)} {{public}}"

        if TrafficInspector.is_readable(data):
            return "warning", f"{item} nga {sender}: {TrafficInspector.decode(data)}"

        return "success", f"{item} nga {sender}: {TrafficInspector.encrypted_preview(data)} {{encrypted}}"

    @staticmethod
    def is_readable(data):
        try:
            text = data.decode()
        except UnicodeDecodeError:
            return False

        return all(char.isprintable() or char in "\r\n\t" for char in text)

    @staticmethod
    def decode(data):
        return data.decode(errors="replace").replace("\r", "").replace("\n", "\\n")[:160]

    @staticmethod
    def encrypted_preview(data):
        return data[:24].hex()

    @staticmethod
    def public_key_summary(data):
        fingerprint = hashlib.sha256(data).hexdigest()[:16]
        preview = data.decode(errors="replace").replace("\n", "")[:64]
        return f"{fingerprint} | {preview}..."


class ManInTheMiddle:
    def __init__(self, listen_host, listen_port, target_host, target_port):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.active_connections = 0
        self.lock = threading.Lock()
        self.ui = MitmCli(listen_host, listen_port, target_host, target_port)

    def start(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.listen_host, self.listen_port))
        listener.listen(5)
        self.ui.update(
            "Proxy po degjon dhe po forward-on traffic.",
            "success",
            "MITM proxy u startua.",
            "success"
        )

        while True:
            client_socket, client_address = listener.accept()
            thread = threading.Thread(
                target=self.handle_connection,
                args=(client_socket, client_address)
            )
            thread.daemon = True
            thread.start()

    def handle_connection(self, client_socket, client_address):
        label = f"{client_address[0]}:{client_address[1]}"

        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((self.target_host, self.target_port))
        except OSError as e:
            client_socket.close()
            self.ui.log(f"Nuk u lidh dot me serverin real: {e}", "error")
            return

        self.change_connections(1)
        self.ui.log(f"Klient i ri permes proxy: {label}", "pending")

        threads = (
            threading.Thread(
                target=self.forward,
                args=(client_socket, server_socket, "client -> server")
            ),
            threading.Thread(
                target=self.forward,
                args=(server_socket, client_socket, "server -> client")
            ),
        )

        for thread in threads:
            thread.daemon = True
            thread.start()

        for thread in threads:
            thread.join()

        self.close(client_socket)
        self.close(server_socket)
        self.change_connections(-1)
        self.ui.log(f"Lidhja proxy u mbyll: {label}", "info")

    def forward(self, source, target, direction):
        try:
            while True:
                data = source.recv(4096)

                if not data:
                    break

                inspected = TrafficInspector.inspect(data, direction)

                if inspected:
                    level, summary = inspected
                    if direction == "client -> server" and not data.startswith(b"-----BEGIN PUBLIC KEY-----"):
                        self.ui.divider("Mesazh i ri")

                    self.ui.log(summary, level)

                target.sendall(data)

        except OSError as e:
            self.ui.log(f"{direction}: lidhja u nderpre ({e})", "warning")

        finally:
            self.close(source)
            self.close(target)

    def change_connections(self, amount):
        with self.lock:
            self.active_connections += amount
            self.ui.set_connections(self.active_connections)

    @staticmethod
    def close(sock):
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

        try:
            sock.close()
        except OSError:
            pass


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=5001)
    parser.add_argument("--target-host", default="127.0.0.1")
    parser.add_argument("--target-port", type=int, default=5000)
    args = parser.parse_args()

    proxy = ManInTheMiddle(
        args.listen_host,
        args.listen_port,
        args.target_host,
        args.target_port
    )
    proxy.start()
