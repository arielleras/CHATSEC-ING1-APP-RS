# CHATSEC - Secure Chatroom

CHATSEC est une application de messagerie sécurisée en Python. La version actuelle du projet n'utilise plus RabbitMQ ni LDAP pour le flux principal : elle repose sur un serveur TCP/TLS local, une base SQLite et une interface client Tkinter remise au propre pour un usage sous Windows 11.

## Fonctionnalités

- Inscription et connexion utilisateur via le serveur local.
- Stockage des comptes dans SQLite avec hash de mot de passe `bcrypt`.
- Transport client/serveur en TLS avec certificat auto-signé.
- Messages privés chiffrés côté client avec RSA.
- Liste des utilisateurs connectés en temps réel.
- Interface client compatible Windows 11 : écrans connexion/inscription, thème sombre, zone de chat, menu, sauvegarde du journal et réglage de la taille de fenêtre.

## Interface Windows 11

L'interface principale est lancée par `main.py`. Elle conserve le parcours classique du projet, mais avec une présentation plus moderne et plus claire :

- splash screen au démarrage ;
- écran de connexion séparé ;
- écran d'inscription séparé ;
- interface de chat avec liste des utilisateurs connectés à gauche ;
- zone de conversation centrale ;
- champ de saisie et bouton d'envoi visibles en bas ;
- menus pour sauvegarder le journal, effacer la conversation, changer le thème, changer la police et gérer la taille de fenêtre.

Le thème par défaut est sombre pour mieux coller à l'esthétique Windows 11 et rester lisible pendant les tests.

## Architecture

```text
Client Tkinter
  main.py -> login.py / signup.py -> chat.py -> interface.py
        |
        | TLS + JSON framed messages
        v
Serveur CHATSEC
  server.py -> database.py -> chatsec.db
```

Fichiers principaux :

- `server.py` : serveur TCP/TLS sur `127.0.0.1:5555`.
- `database.py` : création et accès à la base SQLite `chatsec.db`.
- `chatsec_client.py` : client réseau commun aux interfaces.
- `main.py` : lanceur principal avec splash screen puis interface Windows 11.
- `login.py` / `signup.py` : authentification et création de compte.
- `interface.py` : interface de chat principale.
- `chatsec_gui.py` : client Tkinter direct, utile pour tester rapidement une deuxième fenêtre.
- `generate_cert.py` : génération de `server.crt` et `server.key`.

## Prérequis Windows 11

- Windows 11.
- Python 3.12 ou plus récent installé et disponible dans PowerShell avec la commande `python`.
- Les dépendances Python du fichier `requirements.txt`.

Vérifier Python :

```powershell
python --version
```

Installer les dépendances :

```powershell
python -m pip install -r requirements.txt
```

Option recommandée si tu veux isoler le projet :

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## Premier lancement

Depuis la racine du projet :

```powershell
cd C:\Users\vidav\Documents\EFREI\Ing1\Rattrapage_UE\CHATSEC-ING1-APP-RS
```

Si les fichiers TLS n'existent pas encore, génère le certificat serveur :

```powershell
python generate_cert.py
```

Cette commande crée :

- `server.crt`
- `server.key`

## Lancer le serveur

Ouvre un premier terminal PowerShell dans le dossier du projet, puis lance :

```powershell
python server.py
```

Le serveur écoute sur :

```text
127.0.0.1:5555
```

Garde ce terminal ouvert pendant l'utilisation de l'application.

## Lancer l'interface client principale

Ouvre un deuxième terminal PowerShell dans le même dossier, puis lance :

```powershell
python main.py
```

Ce lanceur affiche le splash screen, puis l'interface Windows 11 de connexion/inscription. Après connexion, l'interface de chat s'ouvre automatiquement.

## Lancer plusieurs clients

Pour tester une conversation, lance une deuxième interface client dans un autre terminal :

```powershell
python main.py
```

Tu peux aussi ouvrir le client direct, plus simple pour les tests rapides :

```powershell
python chatsec_gui.py
```

Exemple de test :

1. Terminal 1 : `python server.py`
2. Terminal 2 : `python main.py`
3. Terminal 3 : `python main.py`
4. Crée ou connecte deux comptes différents.
5. Sélectionne l'autre utilisateur dans la liste des connectés.
6. Envoie un message.

## Commandes utiles

Vérifier que les fichiers Python compilent :

```powershell
python -m py_compile server.py main.py login.py signup.py chat.py interface.py chatsec_client.py
```

Réinitialiser les certificats TLS :

```powershell
Remove-Item server.crt, server.key
python generate_cert.py
```

Réinitialiser la base locale :

```powershell
Remove-Item chatsec.db
python server.py
```

## Notes sur l'ancienne version

Les anciens fichiers liés à RabbitMQ, LDAP et CA sont encore présents dans le dépôt pour historique ou comparaison, mais ils ne sont plus nécessaires pour lancer l'application actuelle.

Le flux actuel est :

```text
python server.py
python main.py
```

Il n'est plus nécessaire de lancer RabbitMQ, OpenLDAP ou `CA/ca_server.py` pour utiliser l'interface client actuelle.
