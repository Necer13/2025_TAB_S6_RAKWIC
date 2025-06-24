import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox
from PIL import Image, ImageTk, JpegImagePlugin
import os
import hashlib
import piexif
import datetime
from sqlalchemy import create_engine, func, String
from sqlalchemy.orm import sessionmaker, selectinload
from orm import Base, User, Photo, Tag
from fpdf import FPDF
import json

JpegImagePlugin._getmp = lambda: None

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
            font=("tahoma", "8", "normal"),
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


def process_exif_for_db(exif_data):
    """
    Processes raw piexif data into a flat, JSON-serializable dictionary
    with human-readable keys.
    """
    if not exif_data:
        return {}

    flat_exif = {}
    # Iterate over all possible IFD sections
    for ifd_name in ("0th", "Exif", "GPS", "1st"):
        ifd_section = exif_data.get(ifd_name)
        if not ifd_section:
            continue

        for tag, value in ifd_section.items():
            # Get tag name from piexif's dictionary
            tag_name = piexif.TAGS.get(ifd_name, {}).get(
                tag, {"name": f"UnknownTag_{tag}"}
            )["name"]

            # Process value to be JSON serializable
            if isinstance(value, bytes):
                # Decode bytes, stripping null characters. Use latin-1 as a robust fallback.
                processed_value = value.strip(b"\x00").decode("latin-1").strip()
            elif (
                isinstance(value, tuple) and len(value) == 2
            ):  # For rational numbers (e.g., FNumber)
                if value[1] != 0:
                    # Represent as a string fraction and a rounded float for easy searching
                    processed_value = (
                        f"{value[0]}/{value[1]} ({round(value[0]/value[1], 2)})"
                    )
                else:
                    processed_value = "0"
            else:
                processed_value = str(value)

            flat_exif[tag_name] = processed_value
    return flat_exif


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def edit_photo(photo_id, gallery_frame, display_names_var):
    edit_win = tk.Toplevel()
    edit_win.title("Edit Photo Details")

    session = Session()
    photo = session.get(Photo, photo_id)
    if not photo:
        messagebox.showerror("Error", "Photo not found.")
        edit_win.destroy()
        session.close()
        return

    fields = {
        "Path": photo.path,
        "Author": photo.author or "",
        "Size (bytes)": photo.attr_size or "",
        "Resolution Width": photo.resolution_width or "",
        "Resolution Height": photo.resolution_height or "",
        "Type": photo.type or "",
        "Date of Creation (YYYY-MM-DD HH:MM:SS)": (
            photo.date_of_creation.strftime("%Y-%m-%d %H:%M:%S")
            if photo.date_of_creation
            else ""
        ),
        "Date of Archivisation (YYYY-MM-DD HH:MM:SS)": (
            photo.date_of_archivisation.strftime("%Y-%m-%d %H:%M:%S")
            if photo.date_of_archivisation
            else ""
        ),
        "EXIF (JSON string)": json.dumps(photo.exif, indent=2) if photo.exif else "{}",
        "Tags (comma-separated)": ", ".join([tag.name for tag in photo.tags]),
    }

    entries = {}
    readonly_fields = ["Size (bytes)", "Resolution Width", "Resolution Height"]

    for idx, (label_text, value) in enumerate(fields.items()):
        lbl = tk.Label(edit_win, text=label_text)
        lbl.grid(row=idx, column=0, sticky="w", padx=5, pady=5)

        if label_text == "EXIF (JSON string)":
            ent = tk.Text(edit_win, width=60, height=10)
            ent.insert("1.0", str(value))
        else:
            ent = tk.Entry(edit_win, width=60)
            ent.insert(0, str(value))

        ent.grid(row=idx, column=1, padx=5, pady=5)
        if label_text in readonly_fields:
            if isinstance(ent, tk.Entry):
                ent.config(state="readonly")
            else:
                ent.config(state="disabled")
        entries[label_text] = ent

    def save_changes():
        try:
            photo.path = entries["Path"].get().strip()
            photo.author = entries["Author"].get().strip() or None
            photo.type = entries["Type"].get().strip() or None

            def parse_date(dt_str):
                dt_str = dt_str.strip()
                if not dt_str:
                    return None
                try:
                    return datetime.datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    messagebox.showerror("Error", f"Invalid date format: {dt_str}")
                    raise

            photo.date_of_creation = parse_date(
                entries["Date of Creation (YYYY-MM-DD HH:MM:SS)"].get()
            )
            photo.date_of_archivisation = parse_date(
                entries["Date of Archivisation (YYYY-MM-DD HH:MM:SS)"].get()
            )

            exif_text = entries["EXIF (JSON string)"].get("1.0", tk.END)
            if exif_text.strip():
                photo.exif = json.loads(exif_text)
            else:
                photo.exif = {}

            # Handle tags
            tag_names_str = entries["Tags (comma-separated)"].get().strip()
            new_tag_names = [
                name.strip() for name in tag_names_str.split(",") if name.strip()
            ]

            photo.tags.clear()
            for tag_name in new_tag_names:
                tag = session.query(Tag).filter_by(name=tag_name).first()
                if not tag:
                    tag = Tag(name=tag_name)
                    session.add(tag)
                photo.tags.append(tag)

            session.commit()
            edit_win.destroy()

            # Refresh gallery
            photos = session.query(Photo).options(selectinload(Photo.tags)).all()
            update_gallery(
                gallery_frame, photos, display_names_var, gallery_frame.last_num_columns
            )

        except Exception as e:
            session.rollback()
            messagebox.showerror("Error", f"Failed to save changes: {str(e)}")

    btn_save = tk.Button(edit_win, text="Save Changes", command=save_changes)
    btn_save.grid(row=len(fields), column=0, columnspan=2, pady=10)

    def on_close():
        session.close()
        edit_win.destroy()

    edit_win.protocol("WM_DELETE_WINDOW", on_close)


def delete_photo(photo_id, gallery_frame, display_names_var):
    if not messagebox.askyesno(
        "Confirm Delete",
        "Are you sure you want to delete this photo? This action cannot be undone.",
    ):
        return

    session = Session()
    try:
        photo_to_delete = session.get(Photo, photo_id)
        if photo_to_delete:
            session.delete(photo_to_delete)
            session.commit()
            # Refresh the gallery
            photos = session.query(Photo).options(selectinload(Photo.tags)).all()
            update_gallery(
                gallery_frame, photos, display_names_var, gallery_frame.last_num_columns
            )
    except Exception as e:
        session.rollback()
        messagebox.showerror("Error", f"Failed to delete photo: {str(e)}")
    finally:
        session.close()


def filter_photos(search_term=None, exif_key=None, exif_value=None):
    """
    Filters photos based on a general search term and/or specific EXIF data.
    """
    session = Session()
    try:
        query = session.query(Photo).options(selectinload(Photo.tags))

        # Apply text search filter
        if search_term and search_term.strip():
            term = f"%{search_term.strip()}%"
            query = query.filter(
                (Photo.path.ilike(term))
                | (Photo.author.ilike(term))
                | (Photo.tags.any(Tag.name.ilike(term)))
            )

        # Apply EXIF filter
        if exif_key and exif_key.strip():
            # This SQLAlchemy syntax safely queries the JSONB/JSON column.
            # It checks if the key exists...
            query = query.filter(Photo.exif[exif_key.strip()].isnot(None))
            # ...and if a value is provided, it checks if the value matches (case-insensitive).
            if exif_value is not None and exif_value.strip():
                query = query.filter(
                    Photo.exif[exif_key.strip()]
                    .as_string()
                    .ilike(f"%{exif_value.strip()}%")
                )

        return query.all()
    except Exception as e:
        messagebox.showerror(
            "Filter Error",
            f"An error occurred during filtering: {e}\nNote: EXIF key might be case-sensitive.",
        )
        return []
    finally:
        session.close()


def add_photo(gallery_frame, display_names_var):
    file_path = filedialog.askopenfilename(
        title="Select a photo",
        filetypes=[("Image Files", "*.jpg *.jpeg *.png *.gif *.bmp")],
    )
    if not file_path:
        return

    exif_dict_for_db = {}
    author = None
    date_of_creation = None

    try:
        img = Image.open(file_path)
        size = os.path.getsize(file_path)
        resolution_width, resolution_height = img.size
        image_type = img.format

        # Correctly read and process EXIF data
        if "exif" in img.info and img.info["exif"]:
            raw_exif = piexif.load(img.info["exif"])
            exif_dict_for_db = process_exif_for_db(raw_exif)

            author = exif_dict_for_db.get("Artist")
            date_str = exif_dict_for_db.get("DateTimeOriginal") or exif_dict_for_db.get(
                "DateTime"
            )
            if date_str:
                try:
                    # piexif format is 'YYYY:MM:DD HH:MM:SS'
                    date_of_creation = datetime.datetime.strptime(
                        date_str, "%Y:%m:%d %H:%M:%S"
                    )
                except ValueError:
                    # Handle if format is different, fallback to None
                    date_of_creation = None

    except Exception as e:
        messagebox.showerror("Error", f"Could not read image or its metadata: {str(e)}")
        return

    session = Session()
    try:
        new_photo = Photo(
            path=file_path,
            author=author,
            attr_size=size,
            resolution_width=resolution_width,
            resolution_height=resolution_height,
            exif=exif_dict_for_db,  # Save the processed, queryable EXIF data
            date_of_creation=date_of_creation,
            date_of_archivisation=datetime.datetime.now(),
            type=image_type,
        )
        session.add(new_photo)
        session.commit()
        # Refresh gallery to show the new photo
        photos = session.query(Photo).options(selectinload(Photo.tags)).all()
        update_gallery(
            gallery_frame, photos, display_names_var, gallery_frame.last_num_columns
        )
    except Exception as e:
        session.rollback()
        messagebox.showerror(
            "Error", f"An error occurred while adding photo to database: {str(e)}"
        )
    finally:
        session.close()


def update_gallery(gallery_frame, photos, display_names_var, max_columns):
    for widget in gallery_frame.winfo_children():
        widget.destroy()

    gallery_frame.image_refs = []
    gallery_frame.visible_photos = photos
    gallery_frame.last_num_columns = max_columns
    col = 0
    row = 0

    for idx, photo in enumerate(photos):
        card = tk.Frame(gallery_frame, bd=1, relief=tk.RIDGE, padx=10, pady=10)
        card.grid(row=row, column=col, padx=10, pady=10, sticky="n")

        try:
            img = Image.open(photo.path)
            img.thumbnail((250, 180))
            if img.mode in ("RGBA", "P"):
                img = img.convert("RGB")
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
            placeholder = tk.Label(
                card, text="No preview", width=25, height=6, bg="gray80"
            )
            placeholder.pack()

        file_name_only = os.path.basename(photo.path)
        title = tk.Label(card, text=file_name_only, font=("Arial", 12, "bold"))
        if display_names_var.get():  # Conditionally pack the title label
            title.pack(pady=(10, 0))
        description = tk.Label(
            card,
            text=f"Author: {photo.author if photo.author else 'N/A'}",
            wraplength=200,
            justify="center",
        )
        description.pack()

        tags_text = ", ".join([tag.name for tag in photo.tags])
        if tags_text:
            tags_label = tk.Label(
                card,
                text=f"Tags: {tags_text}",
                wraplength=200,
                justify="center",
                fg="blue",
            )
            tags_label.pack()

        # Frame for buttons to align them left and right
        button_frame = tk.Frame(card)
        button_frame.pack(fill=tk.X, pady=5)

        edit_btn = tk.Button(
            button_frame,
            text="Edit",
            command=lambda p_id=photo.id: edit_photo(
                p_id, gallery_frame, display_names_var
            ),
        )
        edit_btn.pack(side=tk.LEFT)
        ToolTip(edit_btn, "Edit this photo's details")

        delete_btn = tk.Button(
            button_frame,
            text="Delete",
            bg="#e74c3c",
            fg="white",
            command=lambda p_id=photo.id: delete_photo(
                p_id, gallery_frame, display_names_var
            ),
        )
        delete_btn.pack(side=tk.RIGHT)
        ToolTip(delete_btn, "Delete this photo from the collection")

        col += 1
        if col >= max_columns:
            col = 0
            row += 1


def generate_report(gallery_frame):
    photos = getattr(gallery_frame, "visible_photos", [])
    if not photos:
        messagebox.showwarning(
            "No Photos", "There are no photos to include in the report."
        )
        return

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Add a font that supports a wide range of characters
    try:
        pdf.add_font("ArialUnicode", "", "arial.ttf", uni=True)
        pdf.set_font("ArialUnicode", size=12)
    except RuntimeError:
        messagebox.showwarning(
            "Font Error",
            "arial.ttf not found. Report text may not render correctly. Please place arial.ttf in the script directory.",
        )
        pdf.set_font("Arial", size=12)

    pdf.cell(200, 10, txt="Photo Collection Report", ln=True, align="C")
    pdf.ln(10)

    for photo in photos:
        pdf.add_page()
        try:
            img = Image.open(photo.path)
            img.thumbnail((150, 150))
            thumb_path = f"temp_thumb_{photo.id}.jpg"
            img.save(thumb_path)

            pdf.image(thumb_path, w=60)
            os.remove(thumb_path)
        except Exception as e:
            pdf.cell(0, 10, txt=f"[Could not load image: {e}]", ln=True)

        # Use write() for better handling of non-ASCII characters if font supports it
        pdf.write(5, f"Path: {photo.path}\n")
        pdf.write(5, f"Author: {photo.author if photo.author else 'N/A'}\n")
        pdf.write(5, f"Size: {photo.attr_size} bytes\n")
        pdf.write(
            5, f"Resolution: {photo.resolution_width}x{photo.resolution_height}\n"
        )
        pdf.write(5, f"Type: {photo.type if photo.type else 'N/A'}\n")
        pdf.write(
            5,
            f"Date of Creation: {photo.date_of_creation.strftime('%Y-%m-%d %H:%M:%S') if photo.date_of_creation else 'N/A'}\n",
        )
        pdf.write(
            5,
            f"Date of Archivisation: {photo.date_of_archivisation.strftime('%Y-%m-%d %H:%M:%S') if photo.date_of_archivisation else 'N/A'}\n",
        )

        # Add EXIF data to the report
        if photo.exif:
            pdf.ln(5)
            pdf.set_font("", size=10)
            pdf.write(5, "EXIF Data:\n")
            pdf.set_font("", size=8)
            exif_str = json.dumps(photo.exif, indent=2)
            pdf.multi_cell(0, 5, exif_str)

    output_path = "photo_collection_report.pdf"
    pdf.output(output_path)
    messagebox.showinfo("Report Generated", f"Report saved as {output_path}")


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

    # === Main Controls Frame (Add, Report, Display) ===
    top_controls_frame = tk.Frame(main_window)
    top_controls_frame.pack(fill="x", padx=10, pady=5)

    add_button = tk.Button(
        top_controls_frame,
        text="Add Photo",
        bg="lightblue",
        padx=10,
        command=lambda: add_photo(gallery, display_names_var),
    )
    add_button.pack(side=tk.LEFT, padx=10, pady=10)
    ToolTip(add_button, "Click to add a new photo to your collection.")

    report_button = tk.Button(
        top_controls_frame,
        text="Generate Report",
        bg="lightblue",
        padx=10,
        command=lambda: generate_report(gallery),
    )
    report_button.pack(side=tk.LEFT)
    ToolTip(report_button, "Generate a report of all currently visible photos.")

    display_names_var = tk.BooleanVar(value=True)
    display_names_check = tk.Checkbutton(
        top_controls_frame,
        text="Show Photo Names",
        variable=display_names_var,
        command=lambda: update_gallery(
            gallery, gallery.visible_photos, display_names_var, gallery.last_num_columns
        ),
    )
    display_names_check.pack(side=tk.LEFT, padx=10, pady=10)

    # === Filter and Search Controls Frame ===
    filter_frame = tk.Frame(main_window, bd=1, relief=tk.GROOVE)
    filter_frame.pack(pady=10, padx=10, fill="x")

    # Text search
    tk.Label(filter_frame, text="Search Term:").pack(side=tk.LEFT, padx=(5, 2))
    search_term_entry = tk.Entry(filter_frame, width=30)
    search_term_entry.pack(side=tk.LEFT, padx=(0, 10))
    ToolTip(search_term_entry, "Search by path, author, or tag.")

    # EXIF Filter
    tk.Label(filter_frame, text="EXIF Key:").pack(side=tk.LEFT, padx=(10, 2))
    exif_key_entry = tk.Entry(filter_frame, width=20)
    exif_key_entry.pack(side=tk.LEFT)
    ToolTip(exif_key_entry, "e.g., 'Make', 'Model', 'FNumber', 'LensModel'")

    tk.Label(filter_frame, text="EXIF Value:").pack(side=tk.LEFT, padx=(10, 2))
    exif_value_entry = tk.Entry(filter_frame, width=20)
    exif_value_entry.pack(side=tk.LEFT)
    ToolTip(exif_value_entry, "e.g., 'Canon', '1.8', 'ILCE-7M3'")

    def apply_filters():
        search_term = search_term_entry.get()
        exif_key = exif_key_entry.get()
        exif_value = exif_value_entry.get()
        results = filter_photos(
            search_term=search_term, exif_key=exif_key, exif_value=exif_value
        )
        update_gallery(gallery, results, display_names_var, gallery.last_num_columns)

    def clear_all_filters():
        search_term_entry.delete(0, tk.END)
        exif_key_entry.delete(0, tk.END)
        exif_value_entry.delete(0, tk.END)
        session = Session()
        try:
            all_photos = session.query(Photo).options(selectinload(Photo.tags)).all()
            update_gallery(
                gallery, all_photos, display_names_var, gallery.last_num_columns
            )
        finally:
            session.close()

    apply_button = tk.Button(filter_frame, text="Apply Filters", command=apply_filters)
    apply_button.pack(side=tk.LEFT, padx=10)

    clear_button = tk.Button(filter_frame, text="Clear", command=clear_all_filters)
    clear_button.pack(side=tk.LEFT)

    # === Gallery Display with Scrollbar ===
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

    def on_canvas_configure(event):
        canvas_width = event.width
        card_width_estimate = 300
        num_columns = max(1, canvas_width // card_width_estimate)
        if getattr(gallery, "last_num_columns", 0) != num_columns:
            update_gallery(
                gallery, gallery.visible_photos, display_names_var, num_columns
            )

    canvas.bind("<Configure>", on_canvas_configure)

    # Initial data load
    session = Session()
    try:
        all_photos = session.query(Photo).options(selectinload(Photo.tags)).all()
    except Exception as e:
        messagebox.showerror(
            "Error", f"An error occurred while fetching photos: {str(e)}"
        )
        all_photos = []
    finally:
        session.close()

    update_gallery(gallery, all_photos, display_names_var, 1)

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


# === Main Application Start ===
if __name__ == "__main__":
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

    label_login = tk.Label(
        form_frame, text="Login", bg="white", font=("Helvetica", 14, "bold")
    )
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
