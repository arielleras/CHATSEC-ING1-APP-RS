import tkinter as tk
from pathlib import Path

from PIL import Image, ImageTk


IMAGE_PATH = Path("imgs") / "11.png"
WIDTH, HEIGHT = 700, 500
SPLASH_DELAY_MS = 1200


def show_splash():
    screen = tk.Tk()
    screen.geometry(f"{WIDTH}x{HEIGHT}")
    screen.resizable(False, False)
    screen.title("CHATSEC")

    canvas = tk.Canvas(screen, width=WIDTH, height=HEIGHT, highlightthickness=0)
    canvas.pack(fill="both", expand=True)

    if IMAGE_PATH.exists():
        image = Image.open(IMAGE_PATH).resize((WIDTH, HEIGHT), Image.Resampling.LANCZOS)
        background = ImageTk.PhotoImage(image)
        canvas.background = background
        canvas.create_image(0, 0, anchor=tk.NW, image=background)
    else:
        canvas.configure(bg="#101418")
        canvas.create_text(
            WIDTH // 2,
            HEIGHT // 2,
            text="CHATSEC",
            fill="#e8f0f2",
            font=("Segoe UI", 28, "bold"),
        )

    screen.after(SPLASH_DELAY_MS, screen.destroy)
    screen.mainloop()


if __name__ == "__main__":
    show_splash()
    from login import LoginPage

    LoginPage().main()
