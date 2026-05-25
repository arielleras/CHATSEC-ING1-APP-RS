import re
import threading
import tkinter as tk
from tkinter import ttk

import qrcode
from PIL import Image, ImageTk

from client import ChatsecClient, HOST, PORT


class SignupPage:
    def __init__(self):
        self.client = None
        self.qr_photo = None
        self.signup_username = None
        self.pending_mfa_uri = None
        self._username_after_id = None
        self._checking_username = False
        self.username_available = False
        self.last_username_checked = ""

    def validate_password(self, password):
        if len(password) < 12:
            return "Le mot de passe doit contenir au moins 12 caractères."
        if not re.search(r"[a-z]", password):
            return "Le mot de passe doit contenir au moins une minuscule."
        if not re.search(r"[A-Z]", password):
            return "Le mot de passe doit contenir au moins une majuscule."
        if not re.search(r"\d", password):
            return "Le mot de passe doit contenir au moins un chiffre."
        if not re.search(r"[^\w\s]", password):
            return "Le mot de passe doit contenir au moins un caractère spécial."
        return None

    def show_status(self, message, error=False):
        style = "Error.TLabel" if error else "Status.TLabel"
        self.status_label.configure(text=message, style=style)

    def set_busy(self, busy, mfa_only=False):
        state = "disabled" if busy else "normal"

        if not mfa_only:
            self.register_button.configure(state=state)
            self.back_button.configure(state=state)

        if busy:
            self.confirm_mfa_button.configure(state="disabled")
            self.otp_entry.configure(state="disabled")
        else:
            if self.pending_mfa_uri:
                self.confirm_mfa_button.configure(state="normal")
                self.otp_entry.configure(state="normal")

    def validate_passwords_live(self, *args):
        username = self.USERNAME.get().strip()
        password = self.PASSWORD.get()
        confirm = self.CONFIRM_PASSWORD.get()

        if username and len(username) < 2:
            self.show_status("Nom d'utilisateur trop court.", error=True)
            return False

        if password:
            password_error = self.validate_password(password)
            if password_error:
                self.show_status(password_error, error=True)
                return False

        if confirm and password != confirm:
            self.show_status("Les mots de passe ne correspondent pas.", error=True)
            return False

        if username and self.username_available and self.last_username_checked == username:
            if password and confirm and password == confirm:
                self.show_status("Informations valides.")
                return True
            if not password and not confirm:
                self.show_status("Nom d'utilisateur valide et disponible.")
                return True

        self.show_status(f"Serveur : {HOST}:{PORT}")
        return True

    def schedule_username_check(self, *args):
        username = self.USERNAME.get().strip()

        self.username_available = False
        self.last_username_checked = ""

        if self._username_after_id:
            self.root.after_cancel(self._username_after_id)
            self._username_after_id = None

        if not username:
            self.show_status(f"Serveur : {HOST}:{PORT}")
            return

        if len(username) < 2:
            self.show_status("Nom d'utilisateur trop court.", error=True)
            return

        password = self.PASSWORD.get()
        confirm = self.CONFIRM_PASSWORD.get()

        if password:
            password_error = self.validate_password(password)
            if password_error:
                self.show_status(password_error, error=True)
                return

        if confirm and password != confirm:
            self.show_status("Les mots de passe ne correspondent pas.", error=True)
            return

        self.show_status("Vérification du nom d'utilisateur...")
        self._username_after_id = self.root.after(400, self.check_username_live)

    def check_username_live(self):
        username = self.USERNAME.get().strip()
        if not username or len(username) < 2:
            return

        if self._checking_username:
            return

        self._checking_username = True
        threading.Thread(
            target=self._check_username_worker,
            args=(username,),
            daemon=True
        ).start()

    def _check_username_worker(self, username):
        try:
            client = ChatsecClient()
            result = client.check_username(username)
            client.close()
        except Exception as e:
            result = {"status": "ERROR", "message": f"Erreur réseau : {e}"}

        self.root.after(0, lambda: self._finish_username_check(username, result))

    def _finish_username_check(self, username, result):
        self._checking_username = False

        if username != self.USERNAME.get().strip():
            return

        if result.get("status") == "OK":
            self.username_available = True
            self.last_username_checked = username

            password = self.PASSWORD.get()
            confirm = self.CONFIRM_PASSWORD.get()

            if password:
                password_error = self.validate_password(password)
                if password_error:
                    self.show_status(password_error, error=True)
                    return

            if confirm and password != confirm:
                self.show_status("Les mots de passe ne correspondent pas.", error=True)
                return

            if password and confirm and password == confirm:
                self.show_status("Informations valides.")
            else:
                self.show_status("Nom d'utilisateur valide et disponible.")
        else:
            self.username_available = False
            self.last_username_checked = ""
            self.show_status(result.get("message", "Nom d'utilisateur invalide."), error=True)

    def start_signup(self, event=None):
        username = self.USERNAME.get().strip()
        password = self.PASSWORD.get()
        confirm = self.CONFIRM_PASSWORD.get()

        if not username or not password or not confirm:
            self.show_status("Tous les champs sont obligatoires.", error=True)
            return

        if len(username) < 2:
            self.show_status("Le nom d'utilisateur doit contenir au moins 2 caractères.", error=True)
            return

        if not self.username_available or self.last_username_checked != username:
            self.show_status("Vérifie d'abord un nom d'utilisateur disponible.", error=True)
            return

        password_error = self.validate_password(password)
        if password_error:
            self.show_status(password_error, error=True)
            return

        if password != confirm:
            self.show_status("Les mots de passe ne correspondent pas.", error=True)
            return

        self.set_busy(True)
        self.show_status("Génération du QR code MFA...")

        threading.Thread(
            target=self._prepare_signup_worker,
            args=(username, password),
            daemon=True
        ).start()

    def _prepare_signup_worker(self, username, password):
        try:
            client = ChatsecClient()
            result = client.signup_prepare(username, password)
            client.close()
        except Exception as e:
            result = {"status": "ERROR", "message": f"Erreur réseau : {e}"}

        self.root.after(0, lambda: self._finish_prepare_signup(username, result))

    def _finish_prepare_signup(self, username, result):
        self.set_busy(False)

        if result.get("status") != "OK":
            self.show_status(result.get("message", "Impossible de préparer l'inscription."), error=True)
            return

        self.signup_username = username
        self.pending_mfa_uri = result.get("mfa_uri")

        if not self.pending_mfa_uri:
            self.show_status("QR code MFA introuvable.", error=True)
            return

        self.show_qr_code(self.pending_mfa_uri)
        self.otp_entry.configure(state="normal")
        self.confirm_mfa_button.configure(state="normal")
        self.show_status("Scanne le QR code puis saisis le code MFA.")

    def confirm_signup(self, event=None):
        otp = self.OTP.get().strip()

        if not self.signup_username:
            self.show_status("Aucune inscription en attente.", error=True)
            return

        if not otp:
            self.show_status("Saisis le code MFA.", error=True)
            return

        self.set_busy(True, mfa_only=True)
        self.show_status("Vérification du code MFA...")

        threading.Thread(
            target=self._confirm_signup_worker,
            args=(self.signup_username, otp),
            daemon=True
        ).start()

    def _confirm_signup_worker(self, username, otp):
        try:
            client = ChatsecClient()
            result = client.signup_confirm(username, otp)
            client.close()
        except Exception as e:
            result = {"status": "ERROR", "message": f"Erreur réseau : {e}"}

        self.root.after(0, lambda: self._finish_confirm_signup(result))

    def _finish_confirm_signup(self, result):
        self.set_busy(False)

        if result.get("status") != "OK":
            self.confirm_mfa_button.configure(state="normal")
            self.otp_entry.configure(state="normal")
            self.show_status(result.get("message", "Code MFA invalide."), error=True)
            return

        self.show_status("Compte créé avec succès. Tu peux maintenant te connecter.")
        self.confirm_mfa_button.configure(state="disabled")
        self.register_button.configure(state="disabled")
        self.otp_entry.configure(state="disabled")

    def show_qr_code(self, mfa_uri):
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=10,
            border=2
        )
        qr.add_data(mfa_uri)
        qr.make(fit=True)

        pil_img = qr.make_image(fill_color="black", back_color="white")

        if hasattr(pil_img, "get_image"):
            pil_img = pil_img.get_image()

        pil_img = pil_img.convert("RGB")
        pil_img = pil_img.resize((220, 220), Image.NEAREST)

        self.qr_photo = ImageTk.PhotoImage(pil_img)

        self.qr_label.configure(
            image=self.qr_photo,
            text="",
            compound="none"
        )
        self.qr_label.image = self.qr_photo
        self.qr_label.grid()
        self.qr_label.lift()

        self.mfa_label.configure(
            text="Scanne ce QR code avec Google Authenticator ou une app TOTP."
        )

        self.root.update_idletasks()

    def back_to_login(self):
        self.root.destroy()
        from login import LoginPage
        LoginPage().main()

    def _configure_style(self):
        style = ttk.Style(self.root)
        style.theme_use("clam")

        style.configure("App.TFrame", background="#101418")
        style.configure("Panel.TFrame", background="#182028", borderwidth=1, relief="solid")
        style.configure("Title.TLabel", background="#101418", foreground="#e8f0f2", font=("Segoe UI", 22, "bold"))
        style.configure("Subtitle.TLabel", background="#101418", foreground="#91a0a8", font=("Segoe UI", 10))
        style.configure("Field.TLabel", background="#182028", foreground="#d7e0e4", font=("Segoe UI", 10))
        style.configure("Hint.TLabel", background="#182028", foreground="#91a0a8", font=("Segoe UI", 9))
        style.configure("Status.TLabel", background="#182028", foreground="#7dd3a7", font=("Segoe UI", 9))
        style.configure("Error.TLabel", background="#182028", foreground="#ff9f9f", font=("Segoe UI", 9, "bold"))
        style.configure("TEntry", padding=6)
        style.configure("TButton", padding=(12, 7))
        style.configure("Accent.TButton", background="#2aa36b", foreground="#ffffff")
        style.map(
            "Accent.TButton",
            background=[("active", "#35b779"), ("disabled", "#34443c")]
        )

    def main(self):
        self.root = tk.Tk()
        self.root.geometry("700x820")
        self.root.minsize(650, 760)
        self.root.title("CHATSEC - Inscription")
        self.root.configure(bg="#101418")

        self.USERNAME = tk.StringVar(self.root)
        self.PASSWORD = tk.StringVar(self.root)
        self.CONFIRM_PASSWORD = tk.StringVar(self.root)
        self.OTP = tk.StringVar(self.root)

        self.USERNAME.trace_add("write", self.schedule_username_check)
        self.PASSWORD.trace_add("write", self.validate_passwords_live)
        self.CONFIRM_PASSWORD.trace_add("write", self.validate_passwords_live)

        self._configure_style()

        shell = ttk.Frame(self.root, style="App.TFrame", padding=28)
        shell.pack(fill="both", expand=True)
        shell.columnconfigure(0, weight=1)

        ttk.Label(shell, text="CHATSEC", style="Title.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(
            shell,
            text="Inscription sécurisée avec vérification MFA avant sauvegarde",
            style="Subtitle.TLabel",
        ).grid(row=1, column=0, sticky="w", pady=(4, 24))

        form = ttk.Frame(shell, style="Panel.TFrame", padding=18)
        form.grid(row=2, column=0, sticky="nsew")
        form.columnconfigure(1, weight=1)

        ttk.Label(form, text="Nom d’utilisateur", style="Field.TLabel").grid(
            row=0, column=0, sticky="w", padx=(0, 12), pady=6
        )
        username_entry = ttk.Entry(form, textvariable=self.USERNAME)
        username_entry.grid(row=0, column=1, sticky="ew", pady=6)

        ttk.Label(form, text="Mot de passe", style="Field.TLabel").grid(
            row=1, column=0, sticky="w", padx=(0, 12), pady=6
        )
        password_entry = ttk.Entry(form, textvariable=self.PASSWORD, show="*")
        password_entry.grid(row=1, column=1, sticky="ew", pady=6)

        ttk.Label(
            form,
            text="12 caractères minimum, avec majuscule, minuscule, chiffre et caractère spécial.",
            style="Hint.TLabel",
        ).grid(row=2, column=1, sticky="w", pady=(0, 8))

        ttk.Label(form, text="Confirmer le mot de passe", style="Field.TLabel").grid(
            row=3, column=0, sticky="w", padx=(0, 12), pady=6
        )
        confirm_entry = ttk.Entry(form, textvariable=self.CONFIRM_PASSWORD, show="*")
        confirm_entry.grid(row=3, column=1, sticky="ew", pady=6)

        self.status_label = ttk.Label(
            form,
            text=f"Serveur : {HOST}:{PORT}",
            style="Status.TLabel"
        )
        self.status_label.grid(row=4, column=0, columnspan=2, sticky="w", pady=(12, 8))

        self.mfa_label = ttk.Label(
            form,
            text="Le QR code MFA apparaîtra ici après validation des informations.",
            style="Hint.TLabel"
        )
        self.mfa_label.grid(row=5, column=0, columnspan=2, sticky="w", pady=(12, 8))

        self.qr_label = tk.Label(
            form,
            text="",
            bg="#182028",
            bd=0,
            highlightthickness=0
        )
        self.qr_label.grid(row=6, column=0, columnspan=2, pady=(8, 10), sticky="n")
        self.qr_label.grid_remove()

        ttk.Label(form, text="Code MFA", style="Field.TLabel").grid(
            row=7, column=0, sticky="w", padx=(0, 12), pady=6
        )
        self.otp_entry = ttk.Entry(form, textvariable=self.OTP, state="disabled")
        self.otp_entry.grid(row=7, column=1, sticky="ew", pady=6)

        self.confirm_mfa_button = ttk.Button(
            form,
            text="Valider le code MFA",
            command=self.confirm_signup,
            style="Accent.TButton",
            state="disabled"
        )
        self.confirm_mfa_button.grid(row=8, column=1, sticky="e", pady=(10, 0))

        actions = ttk.Frame(shell, style="App.TFrame")
        actions.grid(row=3, column=0, sticky="ew", pady=(18, 0))
        actions.columnconfigure(0, weight=1)

        self.back_button = ttk.Button(
            actions,
            text="Retour connexion",
            command=self.back_to_login
        )
        self.back_button.grid(row=0, column=0, sticky="w")

        self.register_button = ttk.Button(
            actions,
            text="Continuer vers le MFA",
            command=self.start_signup,
            style="Accent.TButton"
        )
        self.register_button.grid(row=0, column=1, sticky="e")

        confirm_entry.bind("<Return>", self.start_signup)
        self.otp_entry.bind("<Return>", self.confirm_signup)
        username_entry.focus_set()

        self.root.mainloop()


if __name__ == "__main__":
    SignupPage().main()