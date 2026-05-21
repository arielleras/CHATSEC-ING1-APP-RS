import tkinter as tk

from interface import ChatInterface, default_window_size


class Chatroom:
    def on_closing(self):
        self.app.disconnect_from_server()
        self.root.destroy()

    def run(self, user, client):
        self.root = tk.Tk()
        self.root.title(f"CHATSEC - {user}")
        self.root.geometry(default_window_size)
        self.root.minsize(860, 560)

        self.app = ChatInterface(self.root, fullname=user, client=client)
        self.app.default_format()

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()
