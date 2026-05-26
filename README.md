# CHATSEC — Secure Chat Application

## Description

CHATSEC est une application de messagerie sécurisée développée en Python dans le cadre d’un projet de cybersécurité.

L’application permet à plusieurs utilisateurs de communiquer via un serveur sécurisé TLS tout en utilisant :
- une authentification forte MFA/TOTP
- le chiffrement RSA-OAEP des messages
- des signatures RSA
- le hachage bcrypt des mots de passe

Le projet repose sur une architecture client/serveur avec interface graphique Tkinter.

---

## Fonctionnalités

- Authentification utilisateur
- MFA avec TOTP
- Chiffrement RSA-OAEP des messages
- Signatures RSA
- Communication sécurisée via TLS
- Gestion des sessions actives
- Liste des utilisateurs connectés
- Protection anti brute-force
- Base de données SQLite
- Journalisation des événements de sécurité

---

## Technologies utilisées

### Langage
- Python 3

### Interface graphique
- Tkinter

### Réseau / sécurité
- socket
- ssl/TLS
- bcrypt
- pyotp
- pycryptodome

### Base de données
- SQLite3

### Configuration
- python-dotenv

---

## Architecture du projet

```text
CHATSEC/
│
├── main.py
├── server.py
├── chatsec_client.py
├── database.py
├── encryption_decryption.py
├── rsa_signature.py
│
├── interface.py
├── login.py
├── signup.py
│
├── generate_cert.py
├── requirements.txt
├── .env.example
├── .gitignore
```

---

## Architecture de sécurité

### TLS

Les communications client/serveur sont sécurisées via TLS grâce à :
- `server.crt`
- `server.key`

Le serveur utilise :

```python
ssl.PROTOCOL_TLS_SERVER
```

### Authentification

Les mots de passe ne sont jamais stockés en clair.

Ils sont :
- hachés avec bcrypt
- stockés dans SQLite

### MFA / TOTP

L’application utilise :
- `pyotp`
- QR Code MFA
- Google Authenticator compatible

### Chiffrement des messages

Les messages sont :
- chiffrés avec RSA-OAEP
- déchiffrés côté client

### Signature des messages

Chaque message peut être signé via RSA afin de :
- vérifier l’intégrité
- vérifier l’authenticité

### Protection anti brute-force

Le serveur :
- limite le nombre de tentatives de connexion
- bloque temporairement les comptes après plusieurs échecs

Configuration via `.env` :

```env
MAX_LOGIN_ATTEMPTS=5
LOCK_TIME_SECONDS=60
```

---

## Installation

### 1. Cloner le dépôt

```bash
git clone https://github.com/arielleras/CHATSEC-ING1-APP-RS.git
cd CHATSEC-ING1-APP-RS
```

### 2. Créer un environnement virtuel

#### Windows

```bash
python -m venv .venv
.venv\Scripts\activate
```

#### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Installer les dépendances

```bash
pip install -r requirements.txt
```

---

## Configuration

Créer un fichier `.env` à la racine du projet :

```env
HOST=127.0.0.1
PORT=5555

CERT_FILE=server.crt
KEY_FILE=server.key

DB_NAME=chatsec.db

MAX_LOGIN_ATTEMPTS=5
LOCK_TIME_SECONDS=60
```

---

## Génération du certificat TLS

Exécuter :

```bash
python generate_cert.py
```

Cela génère :
- `server.crt`
- `server.key`

Ces fichiers sont ignorés par Git via `.gitignore`.

---

## Lancement du serveur

```bash
python server.py
```

---

## Lancement du client

```bash
python main.py
```

---

## Structure de la base de données

### Tables principales

#### `users`

Stocke :
- les utilisateurs
- les mots de passe hachés
- les clés publiques RSA
- les secrets MFA

#### `pending_signups`

Stocke temporairement :
- les inscriptions en attente
- les secrets MFA avant validation

#### `logs`

Stocke :
- les événements de sécurité
- les connexions
- les erreurs
- les actions serveur

#### `active_sessions`

Stocke :
- les sessions actives
- les utilisateurs connectés
- les identifiants de session