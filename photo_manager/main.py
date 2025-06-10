import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox
from PIL import Image, ImageTk
import os
import hashlib
import piexif
import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from orm import Base, User, Photo  # Assuming User model is defined in orm.py

# Global session factory
Session = None

# === Tooltip Helper ===
class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tipwindow = None
        widget.bind("<Enter>", self.show_tip)
        widget.bind("<Leave>", self.hide_tip)

    def show_tip(self, event=None):
        if self.tipwindow or not self.text:
            return
        x, y, cx, cy = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25
        self.tipwindow = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry("+%d+%d" % (x, y))
        label = tk.Label(
            tw,
            text=self.text,
            justify=tk.LEFT,
            background="#ffffe0",
            relief=tk.SOLID,
            borderwidth=1,
            font=("tahoma", "8", "normal")
        )
        label.pack(ipadx=1)

    def hide_tip(self, event=None):
        tw = self.tipwindow
        self.tipwindow = None
        if tw:
            tw.destroy()


# === Initialize database ===
def init_db():
    global Session
    engine = create_engine("sqlite:///users.db")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def edit_item(name):
    messagebox.showinfo("Edit", f"Editing: {name}")


def save_item(name):
    messagebox.showinfo("Saved", f"Changes saved: {name}")


def search_photos(search_term):
    session = Session()
    try:
        results = (
            session.query(Photo)
            .filter(
                (Photo.path.ilike(f"%{search_term}%")) |
                (Photo.author.ilike(f"%{search_term}%"))
            )
            .all()
        )
        return results
    finally:
        session.close()


def add_photo(gallery_frame):
    file_path = filedialog.askopenfilename(
        title="Select a photo",
        filetypes=[("Image Files", "*.jpg *.jpeg *.png *.gif *.bmp")]
    )
    if not file_path:
        return
    author = None
    try:
        img = Image.open(file_path)
        if "exif" in img.info:
            exif_data = piexif.load(img.info["exif"])
            if piexif.ImageIFD.Artist in exif_data["0th"]:
                author = exif_data["0th"][piexif.ImageIFD.Artist].decode('utf-8')
                print(f"Autor: {author}")
        else:
            exif_data = {}
        size = os.path.getsize(file_path)
        resolution_width, resolution_height = img.size
    except Exception as e:
        messagebox.showerror("Error", f"Nie udało się odczytać obrazu: {str(e)}")
        return
    try:
        if piexif.ImageIFD.DateTime in exif_data["0th"]:
            date_of_creation = exif_data["0th"][piexif.ImageIFD.DateTime].decode('utf-8')
    except KeyError:
        date_of_creation = None
    exif_data = {}
    session = Session()
    if not author:
        author = None
    try:
        new_photo = Photo(
            path=file_path,
            author=author,
            attr_size=size,
            resolution_width=resolution_width,
            resolution_height=resolution_height,
            exif=exif_data,
            date_of_creation=date_of_creation,
            date_of_archivisation=datetime.datetime.now(),
        )
        session.add(new_photo)
        session.commit()
        messagebox.showinfo("Success", "Photo added successfully.")
        photos = session.query(Photo).all()
        update_gallery(gallery_frame, photos)
    except Exception as e:
        session.rollback()
        messagebox.showerror("Error", f"An error occurred while adding photo: {str(e)}")
    finally:
        session.close()


def update_gallery(gallery_frame, photos):
    for widget in gallery_frame.winfo_children():
        widget.destroy()

    gallery_frame.image_refs = []
    max_columns = 3
    col = 0
    row = 0

    for idx, photo in enumerate(photos):
        card = tk.Frame(gallery_frame, bd=1, relief=tk.RIDGE, padx=10, pady=10)
        card.grid(row=row, column=col, padx=10, pady=10, sticky="n")

        try:
            img = Image.open(photo.path)
            img.thumbnail((250, 180))
            img_tk = ImageTk.PhotoImage(img)
        except Exception:
            img_tk = None

        if img_tk:
            img_label = tk.Label(card, image=img_tk)
            img_label.image = img_tk
            img_label.pack()
            gallery_frame.image_refs.append(img_tk)

            tooltip_text = f"Size: {photo.attr_size} bytes\nResolution: {photo.resolution_width}x{photo.resolution_height}"
            ToolTip(img_label, tooltip_text)
        else:
            placeholder = tk.Label(card, text="No preview", width=25, height=6, bg="gray80")
            placeholder.pack()

        file_name_only = os.path.basename(photo.path)
        title = tk.Label(card, text=file_name_only, font=("Arial", 12, "bold"))
        title.pack(pady=(10, 0))
        description = tk.Label(card, text=f"Author: {photo.author}", wraplength=200, justify="center")
        description.pack()

        edit_btn = tk.Button(card, text="Edit", command=lambda n=photo.path: edit_item(n))
        edit_btn.pack(side=tk.LEFT, padx=5, pady=5)
        ToolTip(edit_btn, "Edit this photo's details")

        save_btn = tk.Button(card, text="Save", command=lambda n=photo.path: save_item(n))
        save_btn.pack(side=tk.LEFT, padx=5, pady=5)
        ToolTip(save_btn, "Save changes made to this photo")

        col += 1
        if col >= max_columns:
            col = 0
            row += 1


def open_main_window(username):
    root.destroy()
    main_window = tk.Tk()
    main_window.title("Photo Collection Management System")
    main_window.geometry("1200x800")
    main_window.configure(bg="#f5f5f5")

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

    top_frame = tk.Frame(main_window)
    top_frame.pack()

    search_frame = tk.Frame(main_window)
    search_frame.pack(pady=20)

    search_entry = tk.Entry(search_frame, width=40)
    search_entry.insert(0, "Search photos...")
    search_entry.pack(side=tk.LEFT, padx=5)
    ToolTip(search_entry, "Type a keyword and press Enter to search.")

    search_entry.bind("<FocusIn>", lambda e: search_entry.delete(0, tk.END) if search_entry.get() == "Search photos..." else None)
    search_entry.bind("<FocusOut>", lambda e: search_entry.insert(0, "Search photos...") if not search_entry.get() else None)

    def on_search():
        term = search_entry.get().strip()
        results = search_photos(term)
        update_gallery(gallery, results)

    search_entry.bind("<Return>", lambda e: on_search())

    search_button = tk.Button(search_frame, text="Search", command=on_search)
    search_button.pack(side=tk.LEFT)
    ToolTip(search_button, "Click to perform search.")

    container = tk.Frame(main_window)
    container.pack(fill="both", expand=True, padx=10, pady=10)

    canvas = tk.Canvas(container, bg="#f5f5f5")
    scrollbar = tk.Scrollbar(container, orient="vertical", command=canvas.yview)
    canvas.configure(yscrollcommand=scrollbar.set)

    scrollbar.pack(side="right", fill="y")
    canvas.pack(side="left", fill="both", expand=True)

    gallery = tk.Frame(canvas, bg="#f5f5f5")
    canvas.create_window((0, 0), window=gallery, anchor="nw")

    def on_frame_configure(event):
        canvas.configure(scrollregion=canvas.bbox("all"))

    gallery.bind("<Configure>", on_frame_configure)

    add_button = tk.Button(top_frame, text="Add Photo", bg="lightblue", padx=10, command=lambda: add_photo(gallery))
    add_button.pack(side=tk.LEFT, padx=10, pady=10)
    ToolTip(add_button, "Click to add a new photo to your collection.")

    report_button = tk.Button(top_frame, text="Generate Report", bg="lightblue", padx=10)
    report_button.pack(side=tk.LEFT)
    ToolTip(report_button, "Generate a report of all saved photos.")

    session = Session()
    try:
        all_photos = session.query(Photo).all()
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred while fetching photos: {str(e)}")
        all_photos = []
    finally:
        session.close()
    update_gallery(gallery, all_photos)

    footer = tk.Label(
        main_window,
        text="© 2025 Photo Collection Management System | Database Application Project",
        fg="white",
        bg="#2c3e50",
        height=2,
    )
    footer.pack(fill=tk.X, side=tk.BOTTOM)

    main_window.mainloop()


def login():
    username = entry_username.get().strip()
    password = entry_password.get().strip()

    if not username or not password:
        messagebox.showwarning("Error", "Please enter both username and password.")
        return

    hashed_pw = hash_password(password)

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

    session = Session()
    try:
        existing_user = session.query(User).filter_by(username=username).first()
        if existing_user:
            messagebox.showerror("Error", f"User '{username}' already exists.")
            return

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

form_frame = tk.Frame(root, bg="white", padx=30, pady=30, relief="solid", bd=1)
form_frame.place(relx=0.5, rely=0.5, anchor="center")

label_login = tk.Label(form_frame, text="Login", bg="white", font=("Helvetica", 14, "bold"))
label_login.pack(pady=(0, 20))

label_username = tk.Label(form_frame, text="Username:", bg="white")
label_username.pack(anchor="w")
entry_username = tk.Entry(form_frame, width=30)
entry_username.pack(pady=(0, 15))
ToolTip(entry_username, "Enter your username.")

label_password = tk.Label(form_frame, text="Password:", bg="white")
label_password.pack(anchor="w")
entry_password = tk.Entry(form_frame, show="*", width=30)
entry_password.pack(pady=(0, 20))
ToolTip(entry_password, "Enter your password.")

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
ToolTip(login_btn, "Click to log into your account.")

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
ToolTip(register_btn, "Click to create a new account.")

root.mainloop()