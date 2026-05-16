import socket
import threading

from cli_interface import ServerCli
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

server_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
server_public_key = server_private_key.public_key()


def public_key_to_bytes(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def bytes_to_public_key(key_bytes):
    return serialization.load_pem_public_key(key_bytes)


def encrypt_message(message, public_key):
    return public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def decrypt_message(encrypted_message):
    decrypted = server_private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()

PLAIN_PREFIX = b"plain:"


def read_message(data):
    if data.startswith(PLAIN_PREFIX):
        return data[len(PLAIN_PREFIX):].decode(), False

    return decrypt_message(data), True


clients = {}
clients_lock = threading.Lock()


def client_label(client_address):
    return f"{client_address[0]}:{client_address[1]}"


def set_client(client_address, client_public_key, ui):
    with clients_lock:
        clients[client_address] = client_public_key
        active_clients = len(clients)
        client_keys = client_key_rows()

    ui.set_clients(active_clients, client_keys)


def remove_client(client_address, ui):
    with clients_lock:
        clients.pop(client_address, None)
        active_clients = len(clients)
        client_keys = client_key_rows()

    ui.set_clients(active_clients, client_keys)


def client_key_rows():
    rows = []

    for address, public_key in clients.items():
        label = client_label(address)

        if public_key is None:
            rows.append(f"{label} -> key exchange pending")
            continue

        key_bytes = public_key_to_bytes(public_key)
        rows.append(f"{label} -> {key_fingerprint(key_bytes)} | {key_preview(key_bytes)}")

    return rows


def key_fingerprint(key_bytes):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(key_bytes)
    return digest.finalize().hex()[:16]


def key_preview(key_bytes):
    return key_bytes.decode().replace("\n", "")[:64] + "..."
