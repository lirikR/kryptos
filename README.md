# secureCHAT

Projekt CLI per komunikim klient-server me RSA encryption.


## Startimi normal

Terminali 1:

```powershell
python server.py
```

Terminali 2:

```powershell
python client.py
```

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

Ne klient:

- `1` dergon mesazh te enkriptuar
- `2` dergon mesazh pa encryption vetem per demo
- `3` shfaq public key
- `4` teston lidhjen
- `5` del nga aplikacioni

MITM tregon si duket mesazhi i enkriptuar dhe si duket mesazhi pa encryption.

## Fingerprint i serverit

Serveri shfaq `Server key`. Mund ta verifikosh ne klient:

```powershell
python client.py --server-fingerprint <server-key>
```
