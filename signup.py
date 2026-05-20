import threading
import tkinter as tk
from tkinter import ttk

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
            self.show_status("Username et mot de passe obligatoires.", error=True)
            return
        if len(username) < 2:
            self.show_status("Le username doit contenir au moins 2 caracteres.", error=True)
            return
        if len(password) < 4:
            self.show_status("Le mot de passe doit contenir au moins 4 caracteres.", error=True)
            return
        if password != confirm:
            self.show_status("Les mots de passe ne correspondent pas.", error=True)
            return

        self.set_busy(True)
        self.show_status("Creation du compte...")
        threading.Thread(target=self._signup_worker, args=(username, password), daemon=True).start()

    def _signup_worker(self, username, password):
        signup_client = ChatsecClient()
        signup_result = signup_client.signup(username, password)
        if signup_result.get("status") != "OK":
            self.root.after(0, lambda: self._finish_signup(username, None, signup_result))
            return

        client = ChatsecClient()
        login_result = client.login(username, password)
        self.root.after(0, lambda: self._finish_signup(username, client, login_result))

    def _finish_signup(self, username, client, result):
        self.set_busy(False)
        if result.get("status") == "OK":
            self.client = client
            self.HomeWindow(username)
            return

        if client:
            client.close()
        self.show_status(result.get("message", "Inscription impossible."), error=True)

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
        self.root.geometry("540x420")
        self.root.minsize(500, 380)
        self.root.title("CHATSEC - Inscription")
        self.root.configure(bg="#101418")

        self.USERNAME = tk.StringVar(self.root)
        self.PASSWORD = tk.StringVar(self.root)
        self.CONFIRM_PASSWORD = tk.StringVar(self.root)

        self._configure_style()

        shell = ttk.Frame(self.root, style="App.TFrame", padding=28)
        shell.pack(fill="both", expand=True)
        shell.columnconfigure(0, weight=1)

        ttk.Label(shell, text="Creer un compte", style="Title.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(
            shell,
            text="Le compte est cree sur le serveur CHATSEC local",
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

        ttk.Label(form, text="Confirmation", style="Field.TLabel").grid(row=2, column=0, sticky="w", padx=(0, 12))
        confirm_entry = ttk.Entry(form, textvariable=self.CONFIRM_PASSWORD, show="*")
        confirm_entry.grid(row=2, column=1, sticky="ew", pady=6)

        self.error_label = ttk.Label(form, text=f"Serveur: {HOST}:{PORT}", style="Status.TLabel")
        self.error_label.grid(row=3, column=0, columnspan=2, sticky="w", pady=(10, 0))

        actions = ttk.Frame(shell, style="App.TFrame")
        actions.grid(row=3, column=0, sticky="ew", pady=(18, 0))
        actions.columnconfigure(0, weight=1)

        self.login_button = ttk.Button(actions, text="Connexion", command=self.navigate_to_login)
        self.login_button.grid(row=0, column=0, sticky="w")
        self.signup_button = ttk.Button(actions, text="Creer le compte", command=self.Register, style="Accent.TButton")
        self.signup_button.grid(row=0, column=1, sticky="e")

        confirm_entry.bind("<Return>", self.Register)
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
        style.configure("Title.TLabel", background="#101418", foreground="#e8f0f2", font=("Segoe UI", 21, "bold"))
        style.configure("Subtitle.TLabel", background="#101418", foreground="#91a0a8", font=("Segoe UI", 10))
        style.configure("Field.TLabel", background="#182028", foreground="#d7e0e4", font=("Segoe UI", 10))
        style.configure("Status.TLabel", background="#182028", foreground="#7dd3a7", font=("Segoe UI", 9))
        style.configure("Error.TLabel", background="#182028", foreground="#ff9f9f", font=("Segoe UI", 9))
        style.configure("TEntry", padding=6)
        style.configure("TButton", padding=(12, 7))
        style.configure("Accent.TButton", background="#2aa36b", foreground="#ffffff")
        style.map("Accent.TButton", background=[("active", "#35b779"), ("disabled", "#34443c")])


if __name__ == "__main__":
    SignupPage().main()
