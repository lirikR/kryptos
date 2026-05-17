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
