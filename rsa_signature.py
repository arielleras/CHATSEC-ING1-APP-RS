import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature


class RSASignatureManager:
    """
    Gestionnaire RSA complet et finalisé.
    """

    def __init__(self, key_size=2048):
        self.key_size = key_size
        self.private_key = None
        self.public_key = None

    # --- Gestion des Clés ---

    def generate_keypair(self):
        """Génère une nouvelle paire de clés."""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
        )
        self.public_key = self.private_key.public_key()

    def save_private_key(self, filepath):
        """Sauvegarde la clé privée."""
        if not self.private_key:
            raise ValueError("Pas de clé privée générée.")
        pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(filepath, "wb") as f:
            f.write(pem)

    def save_public_key(self, filepath):
        """Sauvegarde la clé publique."""
        if not self.public_key:
            raise ValueError("Pas de clé publique générée.")
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(filepath, "wb") as f:
            f.write(pem)

    def load_private_key(self, filepath):
        """Charge une clé privée depuis un fichier."""
        with open(filepath, "rb") as f:
            self.private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )
            self.public_key = self.private_key.public_key()

    def load_public_key(self, filepath):
        """
        Charge une clé publique depuis un fichier.
        IMPORTANT: Retourne l'objet clé (pour les tests qui font: key = load(...))
        """
        with open(filepath, "rb") as f:
            pem_data = f.read()
            self.public_key = serialization.load_pem_public_key(pem_data)
            return self.public_key  # <--- CORRECTION ICI : Return ajouté

    def public_key_to_pem_string(self):
        """Retourne la clé publique en string Base64 SANS en-têtes."""
        if not self.public_key:
            raise ValueError("Pas de clé publique.")

        der_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return base64.b64encode(der_bytes).decode('utf-8')

    def pem_string_to_public_key(self, pem_string):
        """Convertit une string Base64 en objet clé publique."""
        try:
            return serialization.load_pem_public_key(pem_string.encode('utf-8'))
        except ValueError:
            der_bytes = base64.b64decode(pem_string)
            return serialization.load_der_public_key(der_bytes)

    # --- Signature ---

    def sign_message(self, message):
        """Signe un message (str ou bytes)."""
        if not self.private_key:
            raise ValueError("Clé privée manquante pour signer.")

        if isinstance(message, bytes):
            msg_bytes = message
        else:
            msg_bytes = message.encode("utf-8")

        signature = self.private_key.sign(
            msg_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')

    def verify_signature(self, message, signature_b64, public_key):
        """Vérifie une signature."""
        try:
            signature = base64.b64decode(signature_b64.encode('utf-8'))

            if isinstance(message, bytes):
                msg_bytes = message
            else:
                msg_bytes = message.encode("utf-8")

            public_key.verify(
                signature,
                msg_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except (InvalidSignature, Exception):
            return False

    # --- Chiffrement et Paquets ---

    def create_signed_message_packet(self, content, sender_name, recipient_name, recipient_public_key):
        """
        Crée un paquet complet {sender, recipient, encrypted_content, signature, algorithm}.
        """
        cipher = padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )

        if isinstance(content, bytes):
            content_bytes = content
        else:
            content_bytes = content.encode('utf-8')

        encrypted_content = recipient_public_key.encrypt(
            content_bytes,
            cipher
        )

        signature = self.sign_message(content)

        return {
            'sender': sender_name,
            'recipient': recipient_name,  # <--- CORRECTION ICI : Ajout du recipient
            'encrypted_content': base64.b64encode(encrypted_content).decode('utf-8'),
            'signature': signature,
            'algorithm': 'RSA-OAEP-SHA256'
        }

    def verify_and_decrypt_message(self, packet, sender_public_key):
        """Déchiffre et vérifie."""
        encrypted_content_b64 = packet.get('encrypted_content')
        signature = packet.get('signature')

        # 1. Déchiffrer
        try:
            encrypted_bytes = base64.b64decode(encrypted_content_b64.encode('utf-8'))
            cipher = padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
            decrypted_bytes = self.private_key.decrypt(
                encrypted_bytes,
                cipher
            )
            content = decrypted_bytes.decode('utf-8')
        except Exception as e:
            return {'valid': False, 'error': f'Déchiffrement échoué: {e}'}

        # 2. Vérifier la signature
        is_valid = self.verify_signature(content, signature, sender_public_key)

        return {
            'valid': is_valid,
            'content': content if is_valid else "[Signature Invalide - Message masqué]",
            'error': None if is_valid else "Signature invalide"
        }

    def print_key_info(self):
        print(f"Clé RSA {self.key_size} bits initialisée.")