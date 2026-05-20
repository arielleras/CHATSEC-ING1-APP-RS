import json
import queue
import socket
import ssl
import threading

from Crypto.PublicKey import RSA

from encryption_decryption import rsa_decrypt, rsa_encrypt


HOST = "127.0.0.1"
PORT = 5555
SERVER_CERT = "server.crt"


class ChatsecClient:
    def __init__(self, host=HOST, port=PORT, cert_file=SERVER_CERT):
        self.host = host
        self.port = port
        self.cert_file = cert_file
        self.sock = None
        self.username = ""
        self.private_key = None
        self.public_key = None
        self.running = False
        self.responses = queue.Queue()
        self.events = queue.Queue()
        self._send_lock = threading.Lock()
        self._request_lock = threading.Lock()

    def signup(self, username, password):
        try:
            self.connect()
            self._send({"action": "SIGNUP", "username": username, "password": password})
            return self._recv_response_blocking()
        except OSError as exc:
            return self._error(f"Impossible de joindre le serveur: {exc}")
        finally:
            self.close()

    def login(self, username, password):
        try:
            self.connect()
            self._send({"action": "LOGIN", "username": username, "password": password})
            response = self._recv_response_blocking()
            if response.get("status") != "OK":
                self.close()
                return response

            self.username = username
            key = RSA.generate(2048)
            self.private_key = key.export_key("PEM")
            self.public_key = key.publickey().export_key("PEM").decode("utf-8")

            self._send({"action": "UPLOAD_KEY", "public_key": self.public_key})
            response = self._recv_response_blocking()
            if response.get("status") != "OK":
                self.close()
                return response

            self.running = True
            threading.Thread(target=self._listen, daemon=True).start()
            return {"status": "OK", "message": "Connecte"}
        except OSError as exc:
            self.close()
            return self._error(f"Impossible de joindre le serveur: {exc}")

    def connect(self):
        context = ssl.create_default_context(cafile=self.cert_file)
        context.check_hostname = False
        raw_sock = socket.create_connection((self.host, self.port), timeout=5)
        self.sock = context.wrap_socket(raw_sock, server_hostname="localhost")

    def list_users(self):
        return self.request({"action": "LIST_USERS"})

    def send_message(self, target, message):
        key_response = self.request({"action": "GET_KEY", "target": target})
        if key_response.get("status") != "OK":
            return key_response

        encrypted = rsa_encrypt(message, key_response["public_key"]).decode("utf-8")
        return self.request({"action": "MESSAGE", "to": target, "content": encrypted})

    def request(self, payload, timeout=6):
        if not self.sock:
            return self._error("Client non connecte")

        with self._request_lock:
            try:
                self._send(payload)
                return self.responses.get(timeout=timeout)
            except (OSError, queue.Empty) as exc:
                return self._error(f"Le serveur ne repond pas: {exc}")

    def close(self):
        self.running = False
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self.sock.close()
            except OSError:
                pass
        self.sock = None

    def _listen(self):
        while self.running:
            message = self._recv()
            if not message:
                break
            if not self._dispatch(message):
                self.responses.put(message)

        if self.running:
            self.events.put(("disconnect",))
        self.running = False

    def _recv_response_blocking(self):
        while True:
            message = self._recv()
            if not message:
                return self._error("Connexion fermee par le serveur")
            if not self._dispatch(message):
                return message

    def _dispatch(self, message):
        action = message.get("action")
        if action == "USER_LIST":
            self.events.put(("users", message.get("users", [])))
            return True

        if action == "MESSAGE":
            sender = message.get("from", "?")
            content = message.get("content", "")
            try:
                decrypted = rsa_decrypt(content, self.private_key).decode("utf-8")
            except Exception as exc:
                decrypted = f"[message indechiffrable: {exc}]"
            self.events.put(("message", sender, decrypted))
            return True

        return False

    def _send(self, data):
        raw = json.dumps(data).encode("utf-8")
        frame = len(raw).to_bytes(4, byteorder="big") + raw
        with self._send_lock:
            self.sock.sendall(frame)

    def _recv(self):
        try:
            raw_size = self._recv_exact(4)
            if raw_size is None:
                return None
            size = int.from_bytes(raw_size, byteorder="big")
            raw = self._recv_exact(size)
            if raw is None:
                return None
            return json.loads(raw.decode("utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def _recv_exact(self, size):
        data = b""
        while len(data) < size:
            chunk = self.sock.recv(size - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    @staticmethod
    def _error(message):
        return {"status": "ERROR", "message": message}
