import tkinter as tk
from tkinter import messagebox
import sqlite3
import hashlib

# === Funkcja inicjalizacji bazy danych ===
def init_db():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

# === Funkcja haszowania hasła ===
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# === Funkcja logowania ===
def login():
    username = entry_username.get().strip()
    password = entry_password.get().strip()

    if not username or not password:
        messagebox.showwarning("Błąd", "Podaj login i hasło.")
        return

    hashed_pw = hash_password(password)

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()

    conn.close()

    if result and result[0] == hashed_pw:
        messagebox.showinfo("Sukces", f"Zalogowano jako: {username}")
    else:
        messagebox.showerror("Błąd", "Nieprawidłowy login lub hasło.")

# === Funkcja rejestracji ===
def register():
    username = entry_username.get().strip()
    password = entry_password.get().strip()

    if not username or not password:
        messagebox.showwarning("Błąd", "Podaj login i hasło.")
        return

    hashed_pw = hash_password(password)

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))
        conn.commit()
        messagebox.showinfo("Rejestracja", f"Użytkownik '{username}' został zarejestrowany.")
    except sqlite3.IntegrityError:
        messagebox.showerror("Błąd", f"Użytkownik '{username}' już istnieje.")
    finally:
        conn.close()

# === Inicjalizacja bazy przy starcie ===
init_db()

# === GUI ===
root = tk.Tk()
root.title("System Zarządzania Kolekcją Zdjęć")
root.geometry("600x400")
root.configure(bg="#f5f5f5")

# Pasek tytułu
header = tk.Frame(root, bg="#2c3e50", height=60)
header.pack(fill="x")
header_label = tk.Label(header, text="System Zarządzania Kolekcją Zdjęć",
                        bg="#2c3e50", fg="white", font=("Helvetica", 16, "bold"))
header_label.pack(pady=15)

# Karta logowania
form_frame = tk.Frame(root, bg="white", padx=30, pady=30, relief="solid", bd=1)
form_frame.place(relx=0.5, rely=0.5, anchor="center")

tk.Label(form_frame, text="Logowanie", bg="white", font=("Helvetica", 14, "bold")).pack(pady=(0, 20))

tk.Label(form_frame, text="Nazwa użytkownika:", bg="white").pack(anchor="w")
entry_username = tk.Entry(form_frame, width=30)
entry_username.pack(pady=(0, 15))

tk.Label(form_frame, text="Hasło:", bg="white").pack(anchor="w")
entry_password = tk.Entry(form_frame, show="*", width=30)
entry_password.pack(pady=(0, 20))

# Przyciski logowania i rejestracji
btn_frame = tk.Frame(form_frame, bg="white")
btn_frame.pack()

login_btn = tk.Button(btn_frame, text="Zaloguj", bg="#3498db", fg="white",
                      padx=10, pady=5, width=12, command=login)
login_btn.pack(side="left", padx=5)

register_btn = tk.Button(btn_frame, text="Zarejestruj", bg="#2ecc71", fg="white",
                         padx=10, pady=5, width=12, command=register)
register_btn.pack(side="right", padx=5)

root.mainloop()
