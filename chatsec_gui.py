"""
Simple Tkinter client for the modified CHATSEC TLS server.

Run:
  python chatsec_gui.py
"""

import tkinter as tk
import queue
from tkinter import messagebox, ttk

from pyotp import otp

from chatsec_client import ChatsecClient, HOST, PORT


class ChatsecApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CHATSEC")
        self.geometry("760x500")
        self.minsize(620, 420)
        self.client = ChatsecClient()
        self.active_user = None

        self.auth_frame = ttk.Frame(self, padding=18)
        self.chat_frame = ttk.Frame(self, padding=10)
        self._build_auth()
        self._build_chat()
        self.show_auth()
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def _build_auth(self):
        title = ttk.Label(self.auth_frame, text="CHATSEC", font=("Segoe UI", 20, "bold"))
        title.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 20))

        ttk.Label(self.auth_frame, text="Username").grid(row=1, column=0, sticky="w")
        self.username_entry = ttk.Entry(self.auth_frame, width=32)
        self.username_entry.grid(row=1, column=1, sticky="ew", pady=5)

        ttk.Label(self.auth_frame, text="Password").grid(row=2, column=0, sticky="w")
        self.password_entry = ttk.Entry(self.auth_frame, show="*", width=32)
        self.password_entry.grid(row=2, column=1, sticky="ew", pady=5)

        ttk.Label(self.auth_frame, text="Code MFA (6 chiffres)").grid(row=3, column=0, sticky="w")
        self.otp_entry = ttk.Entry(self.auth_frame, width=32)
        self.otp_entry.grid(row=3, column=1, sticky="ew", pady=5)

        actions = ttk.Frame(self.auth_frame)
        actions.grid(row=3, column=0, columnspan=2, sticky="e", pady=(14, 0))
        ttk.Button(actions, text="Creer un compte", command=self.signup).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Connexion", command=self.login).pack(side="left")

        self.status_label = ttk.Label(self.auth_frame, text=f"Serveur: {HOST}:{PORT}")
        self.status_label.grid(row=4, column=0, columnspan=2, sticky="w", pady=(18, 0))

        self.auth_frame.columnconfigure(1, weight=1)
        self.password_entry.bind("<Return>", lambda _event: self.login())

    def _build_chat(self):
        self.chat_frame.columnconfigure(1, weight=1)
        self.chat_frame.rowconfigure(1, weight=1)

        header = ttk.Frame(self.chat_frame)
        header.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 8))
        self.connected_label = ttk.Label(header, text="Non connecte")
        self.connected_label.pack(side="left")
        ttk.Button(header, text="Rafraichir", command=self.refresh_users).pack(side="right", padx=(8, 0))
        ttk.Button(header, text="Deconnexion", command=self.logout).pack(side="right")

        left = ttk.Frame(self.chat_frame)
        left.grid(row=1, column=0, sticky="ns", padx=(0, 10))
        ttk.Label(left, text="Connectes").pack(anchor="w")
        self.users_list = tk.Listbox(left, width=22, exportselection=False)
        self.users_list.pack(fill="both", expand=True)
        self.users_list.bind("<<ListboxSelect>>", self.select_user)

        right = ttk.Frame(self.chat_frame)
        right.grid(row=1, column=1, sticky="nsew")
        right.columnconfigure(0, weight=1)
        right.rowconfigure(0, weight=1)

        self.messages = tk.Text(right, wrap="word", state="disabled", height=12)
        self.messages.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(right, orient="vertical", command=self.messages.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.messages.configure(yscrollcommand=scroll.set)

        composer = ttk.Frame(right)
        composer.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        composer.columnconfigure(0, weight=1)
        self.message_entry = ttk.Entry(composer)
        self.message_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        ttk.Button(composer, text="Envoyer", command=self.send_current_message).grid(row=0, column=1)
        self.message_entry.bind("<Return>", lambda _event: self.send_current_message())

    def show_auth(self):
        self.chat_frame.pack_forget()
        self.auth_frame.pack(fill="both", expand=True)
        self.username_entry.focus_set()

    def show_chat(self):
        self.auth_frame.pack_forget()
        self.chat_frame.pack(fill="both", expand=True)
        self.message_entry.focus_set()
        self.after(100, self.poll_events)

    def signup(self):
        username, password = self.credentials()
        if not username or not password:
            messagebox.showwarning("CHATSEC", "Username et password obligatoires.")
            return

        response = self.client.signup(username, password)
        if response and response.get("status") == "OK":
            messagebox.showinfo("CHATSEC", "Compte cree. Tu peux te connecter.")
        else:
            messagebox.showerror("CHATSEC", self.error_text(response))

    def login(self):
        username, password = self.credentials()
        if not username or not password:
            messagebox.showwarning("CHATSEC", "Username et password obligatoires.")
            return

        otp = self.otp_entry.get().strip()
        response = self.client.login(username, password, otp)
        if response.get("status") == "OK":
            self.connected_label.configure(text=f"Connecte: {username}")
            self.show_chat()
            self.refresh_users()
            self.append_message("Systeme", "Connexion etablie.")
        else:
            messagebox.showerror("CHATSEC", self.error_text(response))

    def credentials(self):
        return self.username_entry.get().strip(), self.password_entry.get()

    def refresh_users(self):
        response = self.client.list_users()
        if response.get("status") == "OK":
            self.set_users(response.get("users", []))
        else:
            self.append_message("Systeme", self.error_text(response))

    def select_user(self, _event=None):
        selection = self.users_list.curselection()
        if selection:
            self.active_user = self.users_list.get(selection[0])

    def send_current_message(self):
        message = self.message_entry.get().strip()
        if not message:
            return
        if not self.active_user:
            messagebox.showwarning("CHATSEC", "Selectionne un utilisateur connecte.")
            return

        response = self.client.send_message(self.active_user, message)
        if response.get("status") == "OK":
            self.append_message("Moi -> " + self.active_user, message)
            self.message_entry.delete(0, "end")
        else:
            self.append_message("Systeme", self.error_text(response))

    def poll_events(self):
        while True:
            try:
                event = self.client.events.get_nowait()
            except queue.Empty:
                break

            if event[0] == "users":
                self.set_users(event[1])
            elif event[0] == "message":
                self.append_message(event[1], event[2])
            elif event[0] == "disconnect":
                if self.client.running:
                    self.append_message("Systeme", "Connexion serveur interrompue.")

        if self.client.running:
            self.after(100, self.poll_events)

    def set_users(self, users):
        current = self.active_user
        self.users_list.delete(0, "end")
        for user in users:
            self.users_list.insert("end", user)
        if current in users:
            index = users.index(current)
            self.users_list.selection_set(index)
            self.active_user = current
        else:
            self.active_user = users[0] if users else None
            if users:
                self.users_list.selection_set(0)

    def append_message(self, sender, message):
        self.messages.configure(state="normal")
        self.messages.insert("end", f"{sender}: {message}\n")
        self.messages.see("end")
        self.messages.configure(state="disabled")

    def logout(self):
        self.client.close()
        self.client = ChatsecClient()
        self.active_user = None
        self.users_list.delete(0, "end")
        self.messages.configure(state="normal")
        self.messages.delete("1.0", "end")
        self.messages.configure(state="disabled")
        self.show_auth()

    def on_close(self):
        self.client.close()
        self.destroy()

    @staticmethod
    def error_text(response):
        if not response:
            return "Impossible de joindre le serveur."
        return response.get("message", "Erreur inconnue")


if __name__ == "__main__":
    ChatsecApp().mainloop()
