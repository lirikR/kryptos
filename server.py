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

def handle_client(client_socket, client_address, ui):
    label = client_label(client_address)
    ui.log(f"Klient i ri u lidh: {label}", "pending")
    set_client(client_address, None, ui)

    try:
        client_socket.sendall(public_key_to_bytes(server_public_key))
        ui.log(f"Public key i serverit u dergua te {label}.", "pending")

        client_key_data = client_socket.recv(4096)
        client_public_key = bytes_to_public_key(client_key_data)
        set_client(client_address, client_public_key, ui)

        ui.log(f"Public key i klientit {label} u pranua.", "success")
        ui.log(f"Kanali RSA me {label} eshte aktiv.", "success")

        while True:
            try:
                encrypted_message = client_socket.recv(4096)

                if not encrypted_message:
                    ui.log(f"Klienti {label} u shkeput.", "warning")
                    break

                message, encrypted = read_message(encrypted_message)
                ui.divider("Mesazh i ri")
                if encrypted:
                    ui.log(f"Mesazh i dekriptuar nga {label}: {message}")
                else:
                    ui.log(f"Mesazh pa encryption nga {label}: {message}", "warning")

                if message.lower() == "exit":
                    ui.log(f"Klienti {label} doli nga aplikacioni.", "warning")
                    break

                if message.lower() == "ping":
                    response = "Lidhja me serverin eshte aktive."
                else:
                    response = "Serveri e pranoi mesazhin: " + message

                encrypted_response = encrypt_message(response, client_public_key)
                client_socket.sendall(encrypted_response)
                ui.log(f"Pergjigje e enkriptuar u dergua te {label}.", "success")

            except Exception as e:
                ui.log(f"Gabim gjate komunikimit me {label}: {e}", "error")
                break

    except Exception as e:
        ui.log(f"Gabim gjate lidhjes me {label}: {e}", "error")

    finally:
        remove_client(client_address, ui)
        client_socket.close()
        ui.log(f"Lidhja me klientin {label} u mbyll.", "info")

def start_server():
    host = "127.0.0.1"
    port = 5000

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)

    ui = ServerCli(host, port)
    ui.set_server_key(key_fingerprint(public_key_to_bytes(server_public_key)))
    ui.log("Serveri u startua dhe po pret kliente.", "success")

    while True:
        client_socket, client_address = server.accept()

        thread = threading.Thread(
            target=handle_client,
            args=(client_socket, client_address, ui)
        )
        thread.daemon = True
        thread.start()


if __name__ == "__main__":
    start_server()
