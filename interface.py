import queue
import re
import time
import tkinter as tk
from pathlib import Path
from threading import Thread
from tkinter import messagebox


DEFAULT_SIZE_FILE = Path("default_win_size.txt")


def _read_default_window_size():
    try:
        size = DEFAULT_SIZE_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        size = ""
    return size if re.fullmatch(r"\d{3,4}x\d{3,4}", size) else "860x560"


default_window_size = _read_default_window_size()


class ChatInterface(tk.Frame):
    THEMES = {
        "dark": {
            "bg": "#101418",
            "panel": "#182028",
            "panel_alt": "#202a33",
            "text": "#e8f0f2",
            "muted": "#91a0a8",
            "accent": "#2aa36b",
            "accent_hover": "#35b779",
            "danger": "#ff9f9f",
            "input": "#0d1116",
        },
        "light": {
            "bg": "#edf1f4",
            "panel": "#ffffff",
            "panel_alt": "#f5f7f9",
            "text": "#162029",
            "muted": "#60717d",
            "accent": "#1f7a5a",
            "accent_hover": "#256fb4",
            "danger": "#b42318",
            "input": "#ffffff",
        },
        "hacker": {
            "bg": "#0f0f0f",
            "panel": "#141914",
            "panel_alt": "#111f16",
            "text": "#33ff77",
            "muted": "#8ccf9f",
            "accent": "#2aa36b",
            "accent_hover": "#38c985",
            "danger": "#ff7272",
            "input": "#070907",
        },
    }

    FONTS = {
        "Segoe UI": ("Segoe UI", 10),
        "Helvetica": ("Helvetica", 10),
        "Times": ("Times New Roman", 11),
        "Fixed": ("Consolas", 10),
    }

    def __init__(self, master=None, fullname="", client=None):
        super().__init__(master)
        self.master = master
        self.client = client
        self.username = fullname
        self.selected_user = None
        self.theme_name = "dark"
        self.font_name = "Segoe UI"
        self.closed = False

        if self.client is None:
            raise ValueError("ChatInterface requires an authenticated ChatsecClient.")

        self.pack(fill="both", expand=True)
        self._build_menu()
        self._build_layout()
        self.default_format()
        self.refresh_users()
        self.poll_events()

    def _build_menu(self):
        menu = tk.Menu(self.master)
        self.master.config(menu=menu)

        file_menu = tk.Menu(menu, tearoff=0)
        menu.add_cascade(label="Fichier", menu=file_menu)
        file_menu.add_command(label="Enregistrer le journal", command=self.save_chat)
        file_menu.add_command(label="Effacer la conversation", command=self.clear_chat)
        file_menu.add_separator()
        file_menu.add_command(label="Deconnexion", command=self.logout)
        file_menu.add_command(label="Quitter", command=self.client_exit)

        view_menu = tk.Menu(menu, tearoff=0)
        menu.add_cascade(label="Affichage", menu=view_menu)

        theme_menu = tk.Menu(view_menu, tearoff=0)
        view_menu.add_cascade(label="Theme", menu=theme_menu)
        for key, label in (("dark", "Sombre"), ("light", "Clair"), ("hacker", "Hacker")):
            theme_menu.add_command(label=label, command=lambda name=key: self.set_theme(name))

        font_menu = tk.Menu(view_menu, tearoff=0)
        view_menu.add_cascade(label="Police", menu=font_menu)
        for name in self.FONTS:
            font_menu.add_command(label=name, command=lambda font=name: self.set_font(font))

        view_menu.add_separator()
        view_menu.add_command(label="Sauver la taille actuelle", command=self.save_current_window_size)
        view_menu.add_command(label="Restaurer la taille par defaut", command=self.restore_default_window_size)

        users_menu = tk.Menu(menu, tearoff=0)
        menu.add_cascade(label="Utilisateurs", menu=users_menu)
        users_menu.add_command(label="Rafraichir", command=self.refresh_users)

        help_menu = tk.Menu(menu, tearoff=0)
        menu.add_cascade(label="Aide", menu=help_menu)
        help_menu.add_command(label="A propos", command=self.about_msg)

    def _build_layout(self):
        self.header = tk.Frame(self, padx=18, pady=14)
        self.header.pack(fill="x")

        self.title_label = tk.Label(self.header, text="CHATSEC", font=("Segoe UI", 18, "bold"), anchor="w")
        self.title_label.pack(side="left")

        self.status_label = tk.Label(self.header, text=f"Connecte: {self.username}", anchor="e")
        self.status_label.pack(side="right")

        self.body = tk.Frame(self, padx=14, pady=14)
        self.body.pack(fill="both", expand=True)
        self.body.columnconfigure(1, weight=1)
        self.body.rowconfigure(0, weight=1)

        self.sidebar = tk.Frame(self.body, width=220)
        self.sidebar.grid(row=0, column=0, sticky="nsw", padx=(0, 12))
        self.sidebar.grid_propagate(False)

        self.users_title = tk.Label(self.sidebar, text="Connectes", anchor="w", font=("Segoe UI", 10, "bold"))
        self.users_title.pack(fill="x", pady=(0, 8))

        self.users_list = tk.Listbox(self.sidebar, activestyle="none", exportselection=False, height=14)
        self.users_list.pack(fill="both", expand=True)
        self.users_list.bind("<<ListboxSelect>>", self.on_user_select)

        self.refresh_button = tk.Button(self.sidebar, text="Rafraichir", command=self.refresh_users)
        self.refresh_button.pack(fill="x", pady=(10, 0))

        self.main_panel = tk.Frame(self.body)
        self.main_panel.grid(row=0, column=1, sticky="nsew")
        self.main_panel.columnconfigure(0, weight=1)
        self.main_panel.rowconfigure(1, weight=1)

        self.conversation_title = tk.Label(self.main_panel, text="Selectionne un utilisateur", anchor="w")
        self.conversation_title.grid(row=0, column=0, sticky="ew", pady=(0, 8))

        self.text_frame = tk.Frame(self.main_panel)
        self.text_frame.grid(row=1, column=0, sticky="nsew")
        self.text_frame.columnconfigure(0, weight=1)
        self.text_frame.rowconfigure(0, weight=1)

        self.text_box = tk.Text(self.text_frame, wrap="word", state="disabled", bd=0, padx=12, pady=12)
        self.text_box.grid(row=0, column=0, sticky="nsew")
        self.text_scrollbar = tk.Scrollbar(self.text_frame, command=self.text_box.yview)
        self.text_scrollbar.grid(row=0, column=1, sticky="ns")
        self.text_box.configure(yscrollcommand=self.text_scrollbar.set)
        self.text_box.tag_configure("me", spacing3=6)
        self.text_box.tag_configure("them", spacing3=6)
        self.text_box.tag_configure("system", spacing3=8)

        self.entry_frame = tk.Frame(self.main_panel)
        self.entry_frame.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        self.entry_frame.columnconfigure(0, weight=1)

        self.entry_field = tk.Entry(self.entry_frame)
        self.entry_field.grid(row=0, column=0, sticky="ew", padx=(0, 8), ipady=6)
        self.entry_field.bind("<Return>", self.send_message_event)

        self.send_button = tk.Button(self.entry_frame, text="Envoyer", command=self.send_message)
        self.send_button.grid(row=0, column=1, sticky="e", ipadx=10, ipady=4)

        self.footer_label = tk.Label(self.main_panel, text="Messages chiffres de bout en bout par RSA.", anchor="w")
        self.footer_label.grid(row=3, column=0, sticky="ew", pady=(8, 0))

    def refresh_users(self):
        self.set_status("Actualisation des utilisateurs...")
        self._run_async(self.client.list_users, self._finish_refresh_users)

    def _finish_refresh_users(self, response):
        if response.get("status") == "OK":
            self.set_users(response.get("users", []))
            self.set_status(f"Connecte: {self.username}")
            return
        self.set_status(response.get("message", "Impossible de charger les utilisateurs."), error=True)

    def set_users(self, users):
        previous = self.selected_user
        self.users_list.delete(0, tk.END)
        for user in users:
            self.users_list.insert(tk.END, user)

        if previous in users:
            index = users.index(previous)
            self.users_list.selection_set(index)
            self.selected_user = previous
        elif users:
            self.users_list.selection_set(0)
            self.selected_user = users[0]
        else:
            self.selected_user = None

        self.update_conversation_title()

    def on_user_select(self, event=None):
        selection = self.users_list.curselection()
        self.selected_user = self.users_list.get(selection[0]) if selection else None
        self.update_conversation_title()

    def update_conversation_title(self):
        if self.selected_user:
            self.conversation_title.configure(text=f"Conversation avec {self.selected_user}")
            self.send_button.configure(state="normal")
        else:
            self.conversation_title.configure(text="Aucun autre utilisateur connecte")
            self.send_button.configure(state="disabled")

    def send_message_event(self, event=None):
        self.send_message()

    def send_message(self):
        target = self.selected_user
        message = self.entry_field.get().strip()
        if not message:
            return
        if not target:
            self.set_status("Selectionne un utilisateur avant d'envoyer.", error=True)
            return

        self.entry_field.configure(state="disabled")
        self.send_button.configure(state="disabled")
        self.set_status(f"Envoi a {target}...")
        self._run_async(lambda: self.client.send_message(target, message), lambda response: self._finish_send(target, message, response))

    def _finish_send(self, target, message, response):
        self.entry_field.configure(state="normal")
        self.update_conversation_title()
        self.entry_field.focus_set()

        if response.get("status") == "OK":
            self.entry_field.delete(0, tk.END)
            self.append_message(f"Moi -> {target}", message, "me")
            self.set_status(f"Dernier message envoye a {time.strftime('%H:%M:%S')}")
            return

        self.set_status(response.get("message", "Message non envoye."), error=True)

    def poll_events(self):
        while True:
            try:
                event = self.client.events.get_nowait()
            except queue.Empty:
                break

            if event[0] == "users":
                self.set_users(event[1])
            elif event[0] == "message":
                self.append_message(event[1], event[2], "them")
            elif event[0] == "disconnect":
                self.set_status("Connexion serveur interrompue.", error=True)

        if not self.closed:
            self.after(120, self.poll_events)

    def append_message(self, sender, message, tag="system"):
        self.text_box.configure(state="normal")
        self.text_box.insert(tk.END, f"{time.strftime('%H:%M:%S')}  {sender}\n", tag)
        self.text_box.insert(tk.END, f"{message}\n\n", tag)
        self.text_box.see(tk.END)
        self.text_box.configure(state="disabled")

    def save_chat(self):
        logs_dir = Path("logs")
        logs_dir.mkdir(exist_ok=True)
        filename = logs_dir / f"chat_{time.strftime('%Y%m%d_%H%M%S')}.txt"
        content = self.text_box.get("1.0", tk.END).strip()
        filename.write_text(content, encoding="utf-8")
        self.set_status(f"Journal enregistre: {filename}")

    def clear_chat(self):
        self.text_box.configure(state="normal")
        self.text_box.delete("1.0", tk.END)
        self.text_box.configure(state="disabled")
        self.set_status("Conversation effacee.")

    def save_current_window_size(self):
        size = self.master.geometry().split("+")[0]
        DEFAULT_SIZE_FILE.write_text(size, encoding="utf-8")
        self.set_status(f"Taille par defaut sauvegardee: {size}")

    def restore_default_window_size(self):
        self.master.geometry(_read_default_window_size())

    def logout(self):
        self.disconnect_from_server()
        self.master.destroy()
        from login import LoginPage

        LoginPage().main()

    def client_exit(self):
        self.disconnect_from_server()
        self.master.destroy()

    def disconnect_from_server(self):
        self.closed = True
        if self.client:
            self.client.close()

    def about_msg(self):
        messagebox.showinfo(
            "CHATSEC",
            "Client CHATSEC compatible avec le serveur TCP/TLS local.\n"
            "Authentification SQLite, transport TLS et messages RSA chiffres cote client.",
        )

    def set_status(self, message, error=False):
        colors = self.THEMES[self.theme_name]
        self.status_label.configure(text=message, fg=colors["danger"] if error else colors["muted"])

    def set_font(self, font_name):
        self.font_name = font_name
        font = self.FONTS[font_name]
        self.text_box.configure(font=font)
        self.entry_field.configure(font=font)
        self.users_list.configure(font=font)

    def set_theme(self, theme_name):
        self.theme_name = theme_name
        self._apply_theme()

    def default_format(self):
        self.set_font("Segoe UI")
        self.set_theme("dark")

    def _apply_theme(self):
        colors = self.THEMES[self.theme_name]
        self.configure(bg=colors["bg"])
        self.master.configure(bg=colors["bg"])

        for frame in (self.header, self.body, self.main_panel, self.entry_frame):
            frame.configure(bg=colors["bg"])
        for frame in (self.sidebar, self.text_frame):
            frame.configure(bg=colors["panel"])

        for label in (self.title_label, self.users_title, self.conversation_title):
            label.configure(bg=colors["bg"], fg=colors["text"])
        self.users_title.configure(bg=colors["panel"])
        self.status_label.configure(bg=colors["bg"], fg=colors["muted"])
        self.footer_label.configure(bg=colors["bg"], fg=colors["muted"])

        self.users_list.configure(
            bg=colors["panel_alt"],
            fg=colors["text"],
            selectbackground=colors["accent"],
            selectforeground="#ffffff",
            highlightthickness=0,
            bd=0,
        )
        self.text_box.configure(bg=colors["input"], fg=colors["text"], insertbackground=colors["text"])
        self.text_box.tag_configure("me", foreground=colors["accent"])
        self.text_box.tag_configure("them", foreground=colors["text"])
        self.text_box.tag_configure("system", foreground=colors["muted"])
        self.entry_field.configure(
            bg=colors["input"],
            fg=colors["text"],
            insertbackground=colors["text"],
            relief="flat",
            disabledbackground=colors["panel_alt"],
            disabledforeground=colors["muted"],
        )

        for button in (self.refresh_button, self.send_button):
            button.configure(
                bg=colors["accent"],
                fg="#ffffff",
                activebackground=colors["accent_hover"],
                activeforeground="#ffffff",
                relief="flat",
                bd=0,
                cursor="hand2",
            )

    def _run_async(self, work, done):
        def runner():
            result = work()
            if not self.closed:
                self.after(0, lambda: done(result))

        Thread(target=runner, daemon=True).start()
