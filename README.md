# kryptos

Projekt CLI per komunikim klient-server me RSA encryption.

## Cfare implementon projekti

- `server.py` starton serverin TCP, gjeneron celes RSA dhe pranon mesazhe nga klienti.
- `client.py` lidhet me serverin, merr public key dhe dergon mesazhe te enkriptuara.
- `man_in_the_middle.py` starton nje proxy mes klientit dhe serverit per te treguar dallimin mes traffic te enkriptuar dhe atij plain text.
- `cli_interface.py` kujdeset per shfaqjen e informacionit ne terminal.

## Si te ekzekutohet

Terminali 1:

```powershell
python server.py
```

Terminali 2:

```powershell
python client.py
```

Ne klient zgjedh opsionin `1` per te derguar mesazh te enkriptuar, ose `5` per te dale.

## Test me Man In The Middle

Terminali 1:

```powershell
python server.py
```

Terminali 2:

```powershell
python man_in_the_middle.py
```

Terminali 3:

```powershell
python client.py --mitm
```

Ne klient mund te perdoren keto opsione:

- `1` dergon mesazh te enkriptuar
- `2` dergon mesazh pa encryption vetem per demo
- `3` shfaq public key
- `4` teston lidhjen
- `5` del nga aplikacioni

MITM tregon si duket mesazhi i enkriptuar dhe si duket mesazhi pa encryption.

## Shembull rezultati

Kur klienti dergon nje mesazh te enkriptuar, MITM mund te shfaqe:

```text
Mesazh i kapur nga klienti: 8f3a9c1d4e... {encrypted}
```

Kur klienti dergon mesazh plain text per demo:

```text
Mesazh i kapur nga klienti: pershendetje nga klienti
```

## Fingerprint i serverit

Serveri shfaq `Server key`. Mund ta verifikosh ne klient:

```powershell
python client.py --server-fingerprint <server-key>
```
