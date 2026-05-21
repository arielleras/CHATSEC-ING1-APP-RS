import threading
import tkinter as tk
from tkinter import ttk

from chat import Chatroom
from chatsec_client import ChatsecClient, HOST, PORT



class LoginPage:
    def __init__(self):
        self.client = None

    def Login(self, event=None):
        username = self.USERNAME.get().strip()
        password = self.PASSWORD.get()
        otp = self.OTP.get().strip()

        if not username or not password or not otp:
            self.show_status("Username, mot de passe et code MFA obligatoires.", error=True)
            return

        self.set_busy(True)
        self.show_status("Connexion au serveur...")

        threading.Thread(
            target=self._login_worker,
            args=(username, password, otp),
            daemon=True
        ).start()

    def _login_worker(self, username, password, otp):
        client = ChatsecClient()
        result = client.login(username, password, otp)
        self.root.after(0, lambda: self._finish_login(username, client, result))

    def _finish_login(self, username, client, result):
        self.set_busy(False)
        if result.get("status") == "OK":
            self.client = client
            self.HomeWindow(username)
            return

        client.close()
        self.show_status(result.get("message", "Connexion impossible."), error=True)

    def HomeWindow(self, username=None):
        username = username or self.USERNAME.get().strip()
        self.root.destroy()
        Chatroom().run(user=username, client=self.client)

    def navigate_to_signup(self):
        self.root.destroy()
        from signup import SignupPage

        SignupPage().main()

    def main(self):
        self.root = tk.Tk()
        self.root.geometry("520x360")
        self.root.minsize(480, 340)
        self.root.title("CHATSEC - Connexion")
        self.root.configure(bg="#101418")
        self.OTP = tk.StringVar(self.root)

        self.USERNAME = tk.StringVar(self.root)
        self.PASSWORD = tk.StringVar(self.root)

        self._configure_style()

        shell = ttk.Frame(self.root, style="App.TFrame", padding=28)
        shell.pack(fill="both", expand=True)
        shell.columnconfigure(0, weight=1)

        ttk.Label(shell, text="CHATSEC", style="Title.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(
            shell,
            text="Connexion securisee au serveur local",
            style="Subtitle.TLabel",
        ).grid(row=1, column=0, sticky="w", pady=(4, 24))

        form = ttk.Frame(shell, style="Panel.TFrame", padding=18)
        form.grid(row=2, column=0, sticky="nsew")
        form.columnconfigure(1, weight=1)

        ttk.Label(form, text="Username", style="Field.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 12))
        username_entry = ttk.Entry(form, textvariable=self.USERNAME)
        username_entry.grid(row=0, column=1, sticky="ew", pady=6)

        ttk.Label(form, text="Mot de passe", style="Field.TLabel").grid(row=1, column=0, sticky="w", padx=(0, 12))
        password_entry = ttk.Entry(form, textvariable=self.PASSWORD, show="*")
        password_entry.grid(row=1, column=1, sticky="ew", pady=6)

        ttk.Label(form, text="Code MFA", style="Field.TLabel").grid(row=2, column=0, sticky="w", padx=(0, 12))
        otp_entry = ttk.Entry(form, textvariable=self.OTP)
        otp_entry.grid(row=2, column=1, sticky="ew", pady=6)

        self.error_label = ttk.Label(form, text=f"Serveur: {HOST}:{PORT}", style="Status.TLabel")
        self.error_label.grid(row=3, column=0, columnspan=2, sticky="w", pady=(10, 0))

        actions = ttk.Frame(shell, style="App.TFrame")
        actions.grid(row=3, column=0, sticky="ew", pady=(18, 0))
        actions.columnconfigure(0, weight=1)

        self.signup_button = ttk.Button(actions, text="Creer un compte", command=self.navigate_to_signup)
        self.signup_button.grid(row=0, column=0, sticky="w")
        self.login_button = ttk.Button(actions, text="Connexion", command=self.Login, style="Accent.TButton")
        self.login_button.grid(row=0, column=1, sticky="e")

        password_entry.bind("<Return>", self.Login)
        username_entry.focus_set()
        self.root.mainloop()

    def show_status(self, message, error=False):
        style = "Error.TLabel" if error else "Status.TLabel"
        self.error_label.configure(text=message, style=style)

    def set_busy(self, busy):
        state = "disabled" if busy else "normal"
        self.login_button.configure(state=state)
        self.signup_button.configure(state=state)

    def _configure_style(self):
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("App.TFrame", background="#101418")
        style.configure("Panel.TFrame", background="#182028", borderwidth=1, relief="solid")
        style.configure("Title.TLabel", background="#101418", foreground="#e8f0f2", font=("Segoe UI", 22, "bold"))
        style.configure("Subtitle.TLabel", background="#101418", foreground="#91a0a8", font=("Segoe UI", 10))
        style.configure("Field.TLabel", background="#182028", foreground="#d7e0e4", font=("Segoe UI", 10))
        style.configure("Status.TLabel", background="#182028", foreground="#7dd3a7", font=("Segoe UI", 9))
        style.configure("Error.TLabel", background="#182028", foreground="#ff9f9f", font=("Segoe UI", 9))
        style.configure("TEntry", padding=6)
        style.configure("TButton", padding=(12, 7))
        style.configure("Accent.TButton", background="#2aa36b", foreground="#ffffff")
        style.map("Accent.TButton", background=[("active", "#35b779"), ("disabled", "#34443c")])


if __name__ == "__main__":
    LoginPage().main()
