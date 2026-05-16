from argparse import ArgumentParser
import hashlib
import socket

from cli_interface import ClientCli
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

client_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
client_public_key = client_private_key.public_key()
PLAIN_PREFIX = b"plain:"
INACTIVITY_SECONDS = 60

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
    decrypted = client_private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()

def send_encrypted(client, message, server_public_key):
    encrypted_message = encrypt_message(message, server_public_key)
    client.sendall(encrypted_message)

def send_unencrypted(client, message):
    client.sendall(PLAIN_PREFIX + message.encode())

def recive_response(client):
    encrypted_response = client.recv(4096)

    if not encrypted_response:
        return None

    return decrypt_message(encrypted_response)

def key_fingerprint(key_bytes):
    return hashlib.sha256(key_bytes).hexdigest()[:16]

def resolve_prompt(ui, message):
    value = ui.prompt(message,INACTIVITY_SECONDS)

    while value is None:
        if not handle_inactive_mode(ui):
            return None

        value = ui.prompt(message,INACTIVITY_SECONDS)

    return value

def handle_inactive_mode(ui):
    ui.update(
        "Je aktualisht joaktiv. Seanca eshte ne sleep mode.",
        "Inactive",
        "Nuk pati input per 60 sekonda.",
        "Warning"
    )

    while True:
        choice = ui.prompt("Shkruaj resume per vazhdim ose exit per dalje")

        if choice in ("resume","r"):
            ui.update(
                "Komunikimi tani eshte aktiv perseri.",
                "success",
                "Seanca doli nga sleep mode.",
                "success"
            )
            return True

        if choice in ("exit","e"):
            return False

        ui.log("Opsion jo valid. Shkruaj resume ose exit."," Warning")


    def start_client(host="127.0.0.1", port=5000, expected_server_fingerprint=None):
        ui=ClientCli()
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            client.connect((host, port))

            ui.update(
                f"U lidh me serverin {host}:{port}.",
                "success",
                "Duke bere shkembimin e public keys...",
                "pending"
            )

            server_public_key_data = client.recv(4096)
            server_fingerprint = key_fingerprint(server_public_key_data)

        if expected_server_fingerprint and server_fingerprint != expected_server_fingerprint:
            ui.set_status("Server public key fingerprint nuk perputhet.", "error")
            ui.log(f"Pritur: {expected_server_fingerprint}", "error")
            ui.log(f"Pranuar: {server_fingerprint}", "error")
            return







