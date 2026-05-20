"""
generate_cert.py
----------------
Génère un certificat TLS auto-signé pour le serveur.
À lancer UNE SEULE FOIS avant de démarrer le serveur.

Produit :
  - server.crt  (certificat public)
  - server.key  (clé privée)
"""

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import datetime, ipaddress

def generate_cert():
    # 1. Génération de la clé privée RSA 2048 bits
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # 2. Informations du certificat
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CHATSEC"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    # 3. Construction du certificat
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        # Permet d'utiliser le certificat sur localhost et 127.0.0.1
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256(), default_backend())
    )

    # 4. Sauvegarde de la clé privée
    with open("server.key", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # 5. Sauvegarde du certificat
    with open("server.crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print("[OK] Certificat généré : server.crt + server.key")

if __name__ == "__main__":
    generate_cert()
