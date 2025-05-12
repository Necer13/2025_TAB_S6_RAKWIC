import tkinter as tk
from tkinter import messagebox
import hashlib
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from orm import Base, User  # Assuming User model is defined in orm.py

# Global session factory
Session = None


# === Initialize database ===
def init_db():
    """Initialize database using SQLAlchemy ORM"""
    global Session
    engine = create_engine("sqlite:///users.db")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)


# === Hash password ===
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def edit_item(name):
    messagebox.showinfo("Edit", f"Editing: {name}")


def save_item(name):
    messagebox.showinfo("Saved", f"Changes saved: {name}")


def open_main_window(username):
    root.destroy()
    main_window = tk.Tk()
    main_window.title("Photo Collection Management System")
    main_window.geometry("900x600")
    main_window.configure(bg="#f5f5f5")

    # Header
    header = tk.Frame(main_window, bg="#2c3e50", height=60)
    header.pack(fill="x")
    header_label = tk.Label(
        header,
        text="Photo Collection Management System",
        bg="#2c3e50",
        fg="white",
        font=("Helvetica", 16, "bold"),
    )
    header_label.pack(pady=15)

    # Add/Report buttons
    top_frame = tk.Frame(main_window)
    top_frame.pack()

    add_button = tk.Button(top_frame, text="Add Photo", bg="lightblue", padx=10)
    add_button.pack(side=tk.LEFT, padx=10, pady=10)

    report_button = tk.Button(
        top_frame, text="Generate Report", bg="lightblue", padx=10
    )
    report_button.pack(side=tk.LEFT)

    # Search bar
    search_frame = tk.Frame(main_window)
    search_frame.pack(pady=20)

    search_entry = tk.Entry(search_frame, width=40)
    search_entry.insert(0, "Search photos...")
    search_entry.pack(side=tk.LEFT, padx=5)

    search_button = tk.Button(search_frame, text="Search")
    search_button.pack(side=tk.LEFT)

    # Gallery
    gallery = tk.Frame(main_window)
    gallery.pack()

    photo_data = [
        ("Sunset over the lake", "A beautiful sunset captured over Lake Sniardwy."),
        ("Tatra Mountains", "View of the Tatra Mountains from Kasprowy Wierch."),
        ("Warsaw Old Town", "Colorful townhouses in Warsaw's Old Town."),
        ("Baltic Sea at sunrise", "Baltic Sea at sunrise in Kolobrzeg."),
    ]

    for name, desc in photo_data:
        card = tk.Frame(gallery, bd=1, relief=tk.RIDGE, padx=10, pady=10)
        card.pack(side=tk.LEFT, padx=10, pady=10)

        placeholder = tk.Label(card, text="250x180", width=25, height=6, bg="gray80")
        placeholder.pack()

        title = tk.Label(card, text=name, font=("Arial", 12, "bold"))
        title.pack(pady=(10, 0))

        description = tk.Label(card, text=desc, wraplength=200, justify="center")
        description.pack()

        edit_btn = tk.Button(card, text="Edit", command=lambda n=name: edit_item(n))
        edit_btn.pack(side=tk.LEFT, padx=5, pady=5)

        save_btn = tk.Button(card, text="Save", command=lambda n=name: save_item(n))
        save_btn.pack(side=tk.LEFT, padx=5, pady=5)

    # Footer
    footer = tk.Label(
        main_window,
        text="© 2025 Photo Collection Management System | Database Application Project",
        fg="white",
        bg="#2c3e50",
        height=2,
    )
    footer.pack(fill=tk.X, side=tk.BOTTOM)


def login():
    username = entry_username.get().strip()
    password = entry_password.get().strip()

    if not username or not password:
        messagebox.showwarning("Error", "Please enter both username and password.")
        return

    hashed_pw = hash_password(password)

    # Use ORM session
    session = Session()
    try:
        user = session.query(User).filter_by(username=username).first()
        if user and user.password == hashed_pw:
            messagebox.showinfo("Success", f"Logged in as: {username}")
            open_main_window(username)
        else:
            messagebox.showerror("Error", "Invalid username or password.")
    finally:
        session.close()


def register():
    username = entry_username.get().strip()
    password = entry_password.get().strip()

    if not username or not password:
        messagebox.showwarning("Error", "Please enter both username and password.")
        return

    hashed_pw = hash_password(password)

    # Use ORM session
    session = Session()
    try:
        # Check if user exists
        existing_user = session.query(User).filter_by(username=username).first()
        if existing_user:
            messagebox.showerror("Error", f"User '{username}' already exists.")
            return

        # Create new user
        new_user = User(username=username, password=hashed_pw)
        session.add(new_user)
        session.commit()
        messagebox.showinfo("Registration", f"User '{username}' has been registered.")
    except Exception as e:
        session.rollback()
        messagebox.showerror("Error", f"An error occurred: {str(e)}")
    finally:
        session.close()


init_db()

root = tk.Tk()
root.title("Photo Collection Management System")
root.geometry("900x600")
root.configure(bg="#f5f5f5")

# Header
header = tk.Frame(root, bg="#2c3e50", height=60)
header.pack(fill="x")
header_label = tk.Label(
    header,
    text="Photo Collection Management System",
    bg="#2c3e50",
    fg="white",
    font=("Helvetica", 16, "bold"),
)
header_label.pack(pady=15)

# Login card
form_frame = tk.Frame(root, bg="white", padx=30, pady=30, relief="solid", bd=1)
form_frame.place(relx=0.5, rely=0.5, anchor="center")

tk.Label(form_frame, text="Login", bg="white", font=("Helvetica", 14, "bold")).pack(
    pady=(0, 20)
)

tk.Label(form_frame, text="Username:", bg="white").pack(anchor="w")
entry_username = tk.Entry(form_frame, width=30)
entry_username.pack(pady=(0, 15))

tk.Label(form_frame, text="Password:", bg="white").pack(anchor="w")
entry_password = tk.Entry(form_frame, show="*", width=30)
entry_password.pack(pady=(0, 20))

# Login/Register buttons
btn_frame = tk.Frame(form_frame, bg="white")
btn_frame.pack()

login_btn = tk.Button(
    btn_frame,
    text="Login",
    bg="#3498db",
    fg="white",
    padx=10,
    pady=5,
    width=12,
    command=login,
)
login_btn.pack(side="left", padx=5)

register_btn = tk.Button(
    btn_frame,
    text="Register",
    bg="#2ecc71",
    fg="white",
    padx=10,
    pady=5,
    width=12,
    command=register,
)
register_btn.pack(side="right", padx=5)

root.mainloop()
