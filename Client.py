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

def key_fingerprint(key_bytes):
    return hashlib.sha256(key_bytes).hexdigest()[:16]

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

def receive_response(client):
    encrypted_response = client.recv(4096)

    if not encrypted_response:
        return None

    return decrypt_message(encrypted_response)



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
        "warning"
    )

    while True:
        choice = ui.prompt("Shkruaj resume per vazhdim ose exit per dalje")

        if choice is None:
            continue

        choice = choice.lower()

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

        ui.log("Opsion jo valid. Shkruaj resume ose exit.", "warning")


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
            if not server_public_key_data:
                ui.log("Nuk u pranua public key nga serveri.", "error")
                return
            server_fingerprint = key_fingerprint(server_public_key_data)

            if (expected_server_fingerprint and server_fingerprint != expected_server_fingerprint):
                ui.set_status("Server public key fingerprint nuk perputhet.", "error")
                ui.log(f"Pritur: {expected_server_fingerprint}", "error")
                ui.log(f"Pranuar: {server_fingerprint}", "error")
                return

            ui.log(
                f"Server fingerprint: {server_fingerprint}",
                "info"
            )

            server_public_key = bytes_to_public_key(server_public_key_data)
            client.sendall(public_key_to_bytes(client_public_key))
            ui.update(
                "Komunikimi tani eshte i siguruar me RSA encryption.",
                "success",
                "Shkembimi i public keys perfundoi me sukses.",
                "success"
            )
            while True:
                choice = resolve_prompt(ui, "Zgjedh nje opsion")

                if choice is None:
                    send_encrypted(client, "exit", server_public_key)
                    ui.log("Seanca u mbyll nga sleep mode.", "warning")
                    break

                if choice == "1":
                    message = resolve_prompt(ui, "Shkruaj mesazhin")

                    if message is None:
                        send_encrypted(client, "exit", server_public_key)
                        ui.log("Seanca u mbyll nga sleep mode.", "warning")
                        break

                    if message == "":
                        ui.log("Mesazhi nuk mund te jete i zbrazet.", "warning")
                        continue

                    ui.divider("Mesazh i enkriptuar")
                    send_encrypted(client, message, server_public_key)
                    ui.log("Mesazhi u enkriptua dhe u dergua te serveri.", "success")

                    response = receive_response(client)

                    if response is None:
                        ui.set_status("Serveri e mbylli lidhjen.", "error")
                        break

                    ui.log("Pergjigja nga serveri: " + response)

                    if response.startswith("Klienti nuk dergoi"):
                        break

                elif choice == "2":
                    message = resolve_prompt(ui, "Shkruaj mesazhin pa encryption")

                    if message is None:
                        send_encrypted(client, "exit", server_public_key)
                        ui.log("Seanca u mbyll nga sleep mode.", "warning")
                        break

                    if message == "":
                        ui.log("Mesazhi nuk mund te jete i zbrazet.", "warning")
                        continue

                    ui.divider("Mesazh pa encryption")
                    send_unencrypted(client, message)
                    ui.log("Mesazhi u dergua pa encryption per demonstrim.", "warning")

                    response = receive_response(client)

                    if response is None:
                        ui.set_status("Serveri e mbylli lidhjen.", "error")
                        break

                    ui.log("Pergjigja nga serveri: " + response)

                    if response.startswith("Klienti nuk dergoi"):
                        break

                elif choice == "3":
                    ui.show_panel(
                        "Public key i klientit",
                        public_key_to_bytes(client_public_key).decode()
                    )

                elif choice == "4":
                    ui.divider("Test lidhjeje")
                    send_encrypted(client, "ping", server_public_key)

                    response = receive_response(client)

                    if response is None:
                        ui.set_status("Serveri nuk ktheu pergjigje.", "error")
                        break

                    ui.log("Pergjigja nga serveri: " + response, "success")

                elif choice == "5":
                    ui.divider("Dalje")
                    send_encrypted(client, "exit", server_public_key)
                    ui.log("Duke dale nga aplikacioni...", "warning")
                    break

                else:
                    ui.log("Opsion jo valid. Provo perseri.", "warning")

        except ConnectionRefusedError:
            ui.set_status("Nuk mund te lidhet me serverin.", "error")
            ui.log("Kontrollo a eshte startuar server.py", "warning")

        except Exception as e:
            ui.set_status("Gabim gjate ekzekutimit.", "error")
            ui.log(str(e), "error")

        finally:
            client.close()
            ui.log("Lidhja u mbyll me sukses.")


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--mitm", action="store_true")
    parser.add_argument("--server-fingerprint")
    args = parser.parse_args()

    if args.mitm:
        args.port = 5001

    start_client(args.host, args.port, args.server_fingerprint)
