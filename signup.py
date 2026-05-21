import threading
import tkinter as tk
from tkinter import ttk

import qrcode
from PIL import ImageTk

from chat import Chatroom
from chatsec_client import ChatsecClient, HOST, PORT


class SignupPage:
    def __init__(self):
        self.client = None

    def Register(self, event=None):
        username = self.USERNAME.get().strip()
        password = self.PASSWORD.get()
        confirm = self.CONFIRM_PASSWORD.get()

        if not username or not password:
            self.show_status("Nom d'utilisateur et mot de passe obligatoires.", error=True)
            return
        if len(username) < 2:
            self.show_status("Le nom d'utilisateur doit contenir au moins 2 caractères.", error=True)
            return
        if len(password) < 4:
            self.show_status("Le mot de passe doit contenir au moins 4 caractères.", error=True)
            return
        if password != confirm:
            self.show_status("Les mots de passe ne correspondent pas.", error=True)
            return

        self.set_busy(True)
        self.show_status("Création du compte...")
        threading.Thread(target=self._signup_worker, args=(username, password), daemon=True).start()

    def _signup_worker(self, username, password):
        signup_client = ChatsecClient()
        signup_result = signup_client.signup(username, password)

        self.root.after(
            0,
            lambda: self._show_mfa_qr(username, password, signup_result)
        )

    def _show_mfa_qr(self, username, password, result):
        self.set_busy(False)

        if result.get("status") != "OK":
            self.show_status(result.get("message", "Inscription impossible."), error=True)
            return

        self.pending_username = username
        self.pending_password = password
        self.mfa_uri = result.get("mfa_uri")

        qr_img = qrcode.make(self.mfa_uri)
        qr_img = qr_img.resize((180, 180))

        self.qr_photo = ImageTk.PhotoImage(qr_img)
        self.qr_label.configure(image=self.qr_photo, text="")

        self.show_status("QR code généré. Scanne-le puis entre le code MFA.")
        self.signup_button.configure(text="Valider le MFA", command=self.ValidateMFA)
        self.otp_entry.focus_set()

    def ValidateMFA(self):
        otp = self.OTP.get().strip()

        if not otp:
            self.show_status("Code MFA obligatoire.", error=True)
            return

        self.set_busy(True)
        self.show_status("Vérification du MFA...")

        threading.Thread(
            target=self._mfa_login_worker,
            args=(self.pending_username, self.pending_password, otp),
            daemon=True
        ).start()

    def _mfa_login_worker(self, username, password, otp):
        client = ChatsecClient()
        login_result = client.login(username, password, otp)

        self.root.after(
            0,
            lambda: self._finish_signup(username, client, login_result)
        )

    def _finish_signup(self, username, client, result):
        self.set_busy(False)

        if result.get("status") == "OK":
            self.client = client
            self.HomeWindow(username)
            return

        if client:
            client.close()

        self.show_status(result.get("message", "Code MFA incorrect ou connexion impossible."), error=True)

    def HomeWindow(self, username=None):
        username = username or self.USERNAME.get().strip()
        self.root.destroy()
        Chatroom().run(user=username, client=self.client)

    def navigate_to_login(self):
        self.root.destroy()
        from login import LoginPage
        LoginPage().main()

    def main(self):
        self.root = tk.Tk()
        self.root.geometry("760x620")
        self.root.minsize(680, 560)
        self.root.title("CHATSEC - Inscription")
        self.root.configure(bg="#101418")

        self.USERNAME = tk.StringVar(self.root)
        self.PASSWORD = tk.StringVar(self.root)
        self.CONFIRM_PASSWORD = tk.StringVar(self.root)
        self.OTP = tk.StringVar(self.root)
        self.qr_photo = None

        self._configure_style()

        shell = ttk.Frame(self.root, style="App.TFrame", padding=28)
        shell.pack(fill="both", expand=True)
        shell.columnconfigure(0, weight=1)

        ttk.Label(shell, text="Créer un compte", style="Title.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(
            shell,
            text="Création sécurisée avec Google Authenticator",
            style="Subtitle.TLabel",
        ).grid(row=1, column=0, sticky="w", pady=(4, 24))

        form = ttk.Frame(shell, style="Panel.TFrame", padding=22)
        form.grid(row=2, column=0, sticky="nsew")
        form.columnconfigure(1, weight=1)

        ttk.Label(form, text="Étape 1 : informations du compte", style="Section.TLabel").grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 14)
        )

        ttk.Label(form, text="Nom d'utilisateur", style="Field.TLabel").grid(row=1, column=0, sticky="w", padx=(0, 18))
        username_entry = ttk.Entry(form, textvariable=self.USERNAME)
        username_entry.grid(row=1, column=1, sticky="ew", pady=7)

        ttk.Label(form, text="Mot de passe", style="Field.TLabel").grid(row=2, column=0, sticky="w", padx=(0, 18))
        password_entry = ttk.Entry(form, textvariable=self.PASSWORD, show="*")
        password_entry.grid(row=2, column=1, sticky="ew", pady=7)

        ttk.Label(form, text="Confirmation", style="Field.TLabel").grid(row=3, column=0, sticky="w", padx=(0, 18))
        confirm_entry = ttk.Entry(form, textvariable=self.CONFIRM_PASSWORD, show="*")
        confirm_entry.grid(row=3, column=1, sticky="ew", pady=7)

        ttk.Label(form, text="Étape 2 : Google Authenticator", style="Section.TLabel").grid(
            row=4, column=0, columnspan=2, sticky="w", pady=(26, 10)
        )

        self.qr_label = ttk.Label(
            form,
            text="Le QR code apparaîtra ici après la création du compte.",
            style="Hint.TLabel",
            anchor="center"
        )
        self.qr_label.grid(row=5, column=0, columnspan=2, sticky="ew", pady=(4, 14))

        ttk.Label(form, text="Code MFA", style="Field.TLabel").grid(row=6, column=0, sticky="w", padx=(0, 18))
        self.otp_entry = ttk.Entry(form, textvariable=self.OTP)
        self.otp_entry.grid(row=6, column=1, sticky="ew", pady=7)

        ttk.Label(
            form,
            text="Après le scan, saisis le code à 6 chiffres pour activer le compte.",
            style="Hint.TLabel",
        ).grid(row=7, column=1, sticky="w", pady=(2, 10))

        self.error_label = ttk.Label(form, text=f"Serveur : {HOST}:{PORT}", style="Status.TLabel")
        self.error_label.grid(row=8, column=0, columnspan=2, sticky="w", pady=(12, 0))

        actions = ttk.Frame(shell, style="App.TFrame")
        actions.grid(row=3, column=0, sticky="ew", pady=(18, 0))
        actions.columnconfigure(0, weight=1)

        self.login_button = ttk.Button(actions, text="Connexion", command=self.navigate_to_login)
        self.login_button.grid(row=0, column=0, sticky="w")

        self.signup_button = ttk.Button(actions, text="Créer le compte", command=self.Register, style="Accent.TButton")
        self.signup_button.grid(row=0, column=1, sticky="e")

        confirm_entry.bind("<Return>", self.Register)
        self.otp_entry.bind("<Return>", lambda event: self.ValidateMFA())

        username_entry.focus_set()
        self.root.mainloop()

    def show_status(self, message, error=False):
        style = "Error.TLabel" if error else "Status.TLabel"
        self.error_label.configure(text=message, style=style)

    def set_busy(self, busy):
        state = "disabled" if busy else "normal"
        self.signup_button.configure(state=state)
        self.login_button.configure(state=state)

    def _configure_style(self):
        style = ttk.Style(self.root)
        style.theme_use("clam")

        style.configure("App.TFrame", background="#101418")
        style.configure("Panel.TFrame", background="#182028", borderwidth=1, relief="solid")
        style.configure("Title.TLabel", background="#101418", foreground="#e8f0f2", font=("Segoe UI", 22, "bold"))
        style.configure("Subtitle.TLabel", background="#101418", foreground="#91a0a8", font=("Segoe UI", 10))
        style.configure("Section.TLabel", background="#182028", foreground="#ffffff", font=("Segoe UI", 11, "bold"))
        style.configure("Field.TLabel", background="#182028", foreground="#d7e0e4", font=("Segoe UI", 10))
        style.configure("Hint.TLabel", background="#182028", foreground="#91a0a8", font=("Segoe UI", 9))
        style.configure("Status.TLabel", background="#182028", foreground="#7dd3a7", font=("Segoe UI", 9))
        style.configure("Error.TLabel", background="#182028", foreground="#ff9f9f", font=("Segoe UI", 9))
        style.configure("TEntry", padding=7)
        style.configure("TButton", padding=(12, 7))
        style.configure("Accent.TButton", background="#2aa36b", foreground="#ffffff")
        style.map("Accent.TButton", background=[("active", "#35b779"), ("disabled", "#34443c")])


if __name__ == "__main__":
    SignupPage().main()