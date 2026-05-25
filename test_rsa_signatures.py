"""
test_rsa_signatures.py
======================
Suite de tests pour les signatures RSA dans CHATSEC

À FAIRE : Exécuter avec: python -m pytest test_rsa_signatures.py -v
Ou: python -m unittest test_rsa_signatures.py
"""

import unittest
import json
import os
import tempfile
import shutil
from rsa_signature import RSASignatureManager


# ============================================================================
# TESTS UNITAIRES : Signatures RSA
# ============================================================================

class TestRSASignatureManager(unittest.TestCase):
    """Tests unitaires pour le RSASignatureManager."""

    def setUp(self):
        """Préparation avant chaque test."""
        self.alice_rsa = RSASignatureManager(key_size=2048)
        self.bob_rsa = RSASignatureManager(key_size=2048)

        # Générer les clés
        self.alice_rsa.generate_keypair()
        self.bob_rsa.generate_keypair()

    def tearDown(self):
        """Nettoyage après chaque test."""
        # Nettoyer les fichiers temporaires
        for f in ['alice_test.pem', 'bob_test.pem']:
            if os.path.exists(f):
                os.remove(f)

    # =========================================================================
    # TESTS DE GÉNÉRATION DES CLÉS
    # =========================================================================

    def test_keypair_generation(self):
        """✓ Test: Générer une paire de clés."""
        rsa = RSASignatureManager()
        self.assertIsNone(rsa.private_key)

        rsa.generate_keypair()

        self.assertIsNotNone(rsa.private_key)
        self.assertIsNotNone(rsa.public_key)

    def test_keypair_size(self):
        """✓ Test: Taille de la clé RSA."""
        rsa = RSASignatureManager(key_size=2048)
        rsa.generate_keypair()

        key_size = rsa.private_key.key_size
        self.assertEqual(key_size, 2048)

    # =========================================================================
    # TESTS DE SIGNATURE
    # =========================================================================

    def test_sign_message(self):
        """✓ Test: Signer un message."""
        message = "Bonjour le monde"
        signature = self.alice_rsa.sign_message(message)

        # La signature doit être une chaîne (base64)
        self.assertIsInstance(signature, str)
        self.assertTrue(len(signature) > 0)

    def test_sign_bytes_message(self):
        """✓ Test: Signer des bytes."""
        message = b"Bonjour le monde"
        signature = self.alice_rsa.sign_message(message)

        self.assertIsInstance(signature, str)

    def test_sign_empty_message(self):
        """✓ Test: Signer un message vide."""
        message = ""
        signature = self.alice_rsa.sign_message(message)

        self.assertIsInstance(signature, str)

    def test_sign_long_message(self):
        """✓ Test: Signer un message long."""
        message = "A" * 10000  # 10K caractères
        signature = self.alice_rsa.sign_message(message)

        self.assertIsInstance(signature, str)

    # =========================================================================
    # TESTS DE VÉRIFICATION
    # =========================================================================

    def test_verify_valid_signature(self):
        """✓ Test: Vérifier une signature valide."""
        message = "Test message"
        signature = self.alice_rsa.sign_message(message)

        is_valid = self.bob_rsa.verify_signature(
            message,
            signature,
            self.alice_rsa.public_key
        )

        self.assertTrue(is_valid)

    def test_verify_invalid_signature(self):
        """✓ Test: Vérifier une signature invalide."""
        message = "Test message"
        signature = self.alice_rsa.sign_message(message)

        # Modifier la signature
        bad_signature = signature[:-10] + "AAAAAAAAAA"

        is_valid = self.bob_rsa.verify_signature(
            message,
            bad_signature,
            self.alice_rsa.public_key
        )

        self.assertFalse(is_valid)

    def test_verify_modified_message(self):
        """✓ Test: Message modifié doit échouer."""
        original_message = "Bonjour Bob"
        modified_message = "Bonjour Alice"

        signature = self.alice_rsa.sign_message(original_message)

        is_valid = self.bob_rsa.verify_signature(
            modified_message,
            signature,
            self.alice_rsa.public_key
        )

        self.assertFalse(is_valid)

    def test_verify_wrong_key(self):
        """✓ Test: Mauvaise clé doit échouer."""
        message = "Test"
        signature = self.alice_rsa.sign_message(message)

        # Essayer de vérifier avec la clé de Bob
        is_valid = self.bob_rsa.verify_signature(
            message,
            signature,
            self.bob_rsa.public_key  # ← Mauvaise clé !
        )

        self.assertFalse(is_valid)

    def test_verify_different_message_types(self):
        """✓ Test: Vérifier avec str et bytes."""
        message_str = "Test message"
        message_bytes = b"Test message"

        signature = self.alice_rsa.sign_message(message_str)

        # Vérifier avec bytes
        is_valid = self.bob_rsa.verify_signature(
            message_bytes,
            signature,
            self.alice_rsa.public_key
        )

        self.assertTrue(is_valid)

    # =========================================================================
    # TESTS DE SÉRIALISATION DES CLÉS
    # =========================================================================

    def test_save_and_load_private_key(self):
        """✓ Test: Sauvegarder et charger la clé privée."""
        filepath = 'test_private.pem'

        # Sauvegarder
        self.alice_rsa.save_private_key(filepath)
        self.assertTrue(os.path.exists(filepath))

        # Charger dans un nouveau manager
        alice2 = RSASignatureManager()
        alice2.load_private_key(filepath)

        # Vérifier que c'est la même clé
        message = "Test"
        signature1 = self.alice_rsa.sign_message(message)
        signature2 = alice2.sign_message(message)

        # Les deux signatures doivent vérifier
        is_valid1 = alice2.verify_signature(message, signature1, self.alice_rsa.public_key)
        is_valid2 = self.alice_rsa.verify_signature(message, signature2, alice2.public_key)

        self.assertTrue(is_valid1)
        self.assertTrue(is_valid2)

        # Nettoyer
        os.remove(filepath)

    def test_save_and_load_public_key(self):
        """✓ Test: Sauvegarder et charger la clé publique."""
        filepath = 'test_public.pem'

        # Sauvegarder
        self.alice_rsa.save_public_key(filepath)
        self.assertTrue(os.path.exists(filepath))

        # Charger
        bob_rsa = RSASignatureManager()
        bob_rsa.generate_keypair()
        alice_public = bob_rsa.load_public_key(filepath)

        # Vérifier qu'on peut vérifier les signatures
        message = "Test"
        signature = self.alice_rsa.sign_message(message)
        is_valid = bob_rsa.verify_signature(message, signature, alice_public)

        self.assertTrue(is_valid)

        # Nettoyer
        os.remove(filepath)

    # =========================================================================
    # TESTS DE CONVERSION PEM/BASE64
    # =========================================================================

    def test_public_key_to_pem_string(self):
        """✓ Test: Convertir clé publique en chaîne base64."""
        pem_string = self.alice_rsa.public_key_to_pem_string()

        self.assertIsInstance(pem_string, str)
        self.assertTrue(len(pem_string) > 0)
        # Doit commencer par base64
        self.assertIn('MII', pem_string[:10])

    def test_pem_string_to_public_key(self):
        """✓ Test: Convertir base64 en clé publique."""
        # Obtenir la clé en base64
        pem_string = self.alice_rsa.public_key_to_pem_string()

        # Convertir en clé
        bob_rsa = RSASignatureManager()
        alice_public = bob_rsa.pem_string_to_public_key(pem_string)

        # Vérifier qu'on peut l'utiliser
        message = "Test"
        signature = self.alice_rsa.sign_message(message)
        is_valid = bob_rsa.verify_signature(message, signature, alice_public)

        self.assertTrue(is_valid)

    # =========================================================================
    # TESTS DE PAQUETS COMPLETS (signature + chiffrement)
    # =========================================================================

    def test_create_signed_encrypted_packet(self):
        """✓ Test: Créer un paquet signé et chiffré."""
        message = "Secret message for Bob"

        packet = self.alice_rsa.create_signed_message_packet(
            content=message,
            sender_name="alice",
            recipient_name="bob",
            recipient_public_key=self.bob_rsa.public_key
        )

        # Vérifier la structure du paquet
        self.assertEqual(packet['sender'], 'alice')
        self.assertEqual(packet['recipient'], 'bob')
        self.assertIn('encrypted_content', packet)
        self.assertIn('signature', packet)
        self.assertIn('algorithm', packet)

    def test_verify_and_decrypt_message(self):
        """✓ Test: Vérifier et déchiffrer un message complet."""
        message = "Bonjour Bob!"

        # Alice crée le paquet
        packet = self.alice_rsa.create_signed_message_packet(
            content=message,
            sender_name="alice",
            recipient_name="bob",
            recipient_public_key=self.bob_rsa.public_key
        )

        # Bob le déchiffre et vérifie
        result = self.bob_rsa.verify_and_decrypt_message(
            packet,
            self.alice_rsa.public_key
        )

        # Vérifier le résultat
        self.assertTrue(result['valid'])
        self.assertEqual(result['content'], message)
        self.assertIsNone(result['error'])

    def test_verify_and_decrypt_with_wrong_key(self):
        """✓ Test: Déchiffrement échoue avec mauvaise clé."""
        message = "Secret"

        # Alice crée le paquet pour Bob
        packet = self.alice_rsa.create_signed_message_packet(
            content=message,
            sender_name="alice",
            recipient_name="bob",
            recipient_public_key=self.bob_rsa.public_key
        )

        # Charlie essaie de le déchiffrer
        charlie_rsa = RSASignatureManager()
        charlie_rsa.generate_keypair()

        result = charlie_rsa.verify_and_decrypt_message(
            packet,
            self.alice_rsa.public_key
        )

        # Doit échouer
        self.assertFalse(result['valid'])


# ============================================================================
# TESTS D'INTÉGRATION : Client CHATSEC
# ============================================================================

class TestChatSecClientRSA(unittest.TestCase):
    """Tests d'intégration pour le client CHATSEC avec RSA."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        os.chdir(self.temp_dir)

    def tearDown(self):
        os.chdir('..')
        shutil.rmtree(self.temp_dir)

    def test_client_initialization(self):
        """✓ Test: Initialiser un client."""
        from chatsec_client import ChatsecClient as ChatSecClient
        client = ChatSecClient()
        self.assertIsNotNone(client.rsa_manager)

    def test_client_rsa_manager(self):
        """✓ Test: RSASignatureManager disponible."""
        from chatsec_client import ChatsecClient as ChatSecClient
        client = ChatSecClient()
        client.rsa_manager.generate_keypair()
        self.assertIsNotNone(client.rsa_manager.public_key)
        self.assertIsNotNone(client.rsa_manager.private_key)

    def test_client_send_receive_message(self):
        """✓ Test: Envoyer et recevoir un message signé."""
        from chatsec_client import ChatsecClient as ChatSecClient

        alice = ChatSecClient()
        bob = ChatSecClient()

        alice.rsa_manager.generate_keypair()
        bob.rsa_manager.generate_keypair()

        bob_public_pem = bob.rsa_manager.public_key_to_pem_string()
        alice.peer_public_keys['bob'] = alice.rsa_manager.pem_string_to_public_key(bob_public_pem)

        packet = alice.rsa_manager.create_signed_message_packet(
            content="Bonjour Bob!",
            sender_name='alice',
            recipient_name='bob',
            recipient_public_key=bob.rsa_manager.public_key
        )

        alice_public_pem = alice.rsa_manager.public_key_to_pem_string()
        sender_key = bob.rsa_manager.pem_string_to_public_key(alice_public_pem)
        result = bob.rsa_manager.verify_and_decrypt_message(packet, sender_key)

        self.assertTrue(result['valid'])
        self.assertEqual(result['content'], "Bonjour Bob!")
# ============================================================================
# TESTS DE PERFORMANCE
# ============================================================================

class TestRSAPerformance(unittest.TestCase):
    """Tests de performance pour RSA."""

    def setUp(self):
        self.rsa = RSASignatureManager(key_size=2048)
        self.rsa.generate_keypair()

    def test_signature_speed(self):
        """⏱️ Test: Performance de la signature."""
        import time

        message = "Test message" * 100  # Message de 1200 chars

        start = time.time()
        for _ in range(10):
            self.rsa.sign_message(message)
        elapsed = time.time() - start

        avg_time = elapsed / 10
        print(f"\n⏱️ Signature moyenne: {avg_time * 1000:.2f}ms")

        # Doit être < 500ms par signature
        self.assertLess(avg_time, 0.5)

    def test_verification_speed(self):
        """⏱️ Test: Performance de la vérification."""
        import time

        message = "Test message" * 100
        signature = self.rsa.sign_message(message)

        start = time.time()
        for _ in range(10):
            self.rsa.verify_signature(message, signature, self.rsa.public_key)
        elapsed = time.time() - start

        avg_time = elapsed / 10
        print(f"⏱️ Vérification moyenne: {avg_time * 1000:.2f}ms")

        # Doit être < 500ms par vérification
        self.assertLess(avg_time, 0.5)


# ============================================================================
# TESTS DE CAS LIMITES
# ============================================================================

class TestEdgeCases(unittest.TestCase):
    """Tests des cas limites et erreurs."""

    def setUp(self):
        self.rsa = RSASignatureManager()
        self.rsa.generate_keypair()

    def test_empty_signature_verification(self):
        """✓ Test: Vérifier une signature vide."""
        is_valid = self.rsa.verify_signature("message", "", self.rsa.public_key)
        self.assertFalse(is_valid)

    def test_unicode_message(self):
        """✓ Test: Signer un message avec Unicode."""
        message = "Bonjour! 你好! مرحبا! 🔐"
        signature = self.rsa.sign_message(message)

        is_valid = self.rsa.verify_signature(message, signature, self.rsa.public_key)
        self.assertTrue(is_valid)

    def test_very_long_message(self):
        """✓ Test: Signer un très long message."""
        message = "A" * 100000  # 100K chars
        signature = self.rsa.sign_message(message)

        is_valid = self.rsa.verify_signature(message, signature, self.rsa.public_key)
        self.assertTrue(is_valid)

    def test_special_characters(self):
        """✓ Test: Caractères spéciaux."""
        message = "!@#$%^&*()_+-=[]{}|;:',.<>?/~`"
        signature = self.rsa.sign_message(message)

        is_valid = self.rsa.verify_signature(message, signature, self.rsa.public_key)
        self.assertTrue(is_valid)


# ============================================================================
# LANCEUR DE TESTS
# ============================================================================

if __name__ == '__main__':
    # Exécuter avec pytest pour plus de détails
    # python -m pytest test_rsa_signatures.py -v

    # Ou avec unittest
    # python test_rsa_signatures.py

    # Créer une suite de tests
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Ajouter tous les tests
    suite.addTests(loader.loadTestsFromTestCase(TestRSASignatureManager))
    suite.addTests(loader.loadTestsFromTestCase(TestChatSecClientRSA))
    suite.addTests(loader.loadTestsFromTestCase(TestRSAPerformance))
    suite.addTests(loader.loadTestsFromTestCase(TestEdgeCases))

    # Exécuter
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite)