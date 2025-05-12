from sqlalchemy import Column, Integer, String, Boolean, Date, ForeignKey, Table, JSON
from sqlalchemy.orm import relationship, composite, declarative_base

Base = declarative_base()

# Association tables
table_user_archive = Table(
    "user_archive",
    Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id"), primary_key=True),
    Column("archive_id", Integer, ForeignKey("archives.id"), primary_key=True),
)

table_photo_category = Table(
    "photo_category",
    Base.metadata,
    Column("photo_id", Integer, ForeignKey("photos.id"), primary_key=True),
    Column("category_id", Integer, ForeignKey("photo_categories.id"), primary_key=True),
)

table_photo_tag = Table(
    "photo_tag",
    Base.metadata,
    Column("photo_id", Integer, ForeignKey("photos.id"), primary_key=True),
    Column("tag_id", Integer, ForeignKey("tags.id"), primary_key=True),
)


# Value object for PhotoAttributes
class PhotoAttributes:
    def __init__(
        self,
        size,
        resolution_width,
        resolution_height,
        exif,
        type,
        date_of_creation,
        date_of_archivisation,
        author,
    ):
        self.size = size
        self.resolution_width = resolution_width
        self.resolution_height = resolution_height
        self.exif = exif
        self.type = type
        self.date_of_creation = date_of_creation
        self.date_of_archivisation = date_of_archivisation
        self.author = author

    def __composite_values__(self):
        return (
            self.size,
            self.resolution_width,
            self.resolution_height,
            self.exif,
            self.type,
            self.date_of_creation,
            self.date_of_archivisation,
            self.author,
        )

    def __repr__(self):
        return (
            f"<PhotoAttributes(size={self.size}, resolution=({self.resolution_width}, {self.resolution_height}),"
            f" type={self.type}, created={self.date_of_creation}, archived={self.date_of_archivisation}, author={self.author})>"
        )


# Core models
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    admin_permissions = Column(Boolean, default=False)
    date_of_update = Column(Date)

    archives_owned = relationship("Archive", back_populates="owner")
    archives = relationship(
        "Archive", secondary=table_user_archive, back_populates="users"
    )


class Archive(Base):
    __tablename__ = "archives"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    path = Column(String, nullable=False)
    size = Column(Integer)
    date_of_creation = Column(Date)
    date_of_update = Column(Date)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    owner = relationship("User", back_populates="archives_owned")
    users = relationship(
        "User", secondary=table_user_archive, back_populates="archives"
    )
    photos = relationship("Photo", back_populates="archive")


class Photo(Base):
    __tablename__ = "photos"

    id = Column(Integer, primary_key=True)
    path = Column(String, nullable=False)

    # Composite attributes
    attr_size = Column("attr_size", Integer)
    resolution_width = Column("res_w", Integer)
    resolution_height = Column("res_h", Integer)
    exif = Column(JSON)
    type = Column(String)
    date_of_creation = Column(Date)
    date_of_archivisation = Column(Date)
    author = Column(String)

    attributes = composite(
        PhotoAttributes,
        attr_size,
        resolution_width,
        resolution_height,
        exif,
        type,
        date_of_creation,
        date_of_archivisation,
        author,
    )

    archive_id = Column(Integer, ForeignKey("archives.id"))
    archive = relationship("Archive", back_populates="photos")

    categories = relationship(
        "PhotoCategory", secondary=table_photo_category, back_populates="photos"
    )
    tags = relationship("Tag", secondary=table_photo_tag, back_populates="photos")


class PhotoCategory(Base):
    __tablename__ = "photo_categories"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    parent_id = Column(Integer, ForeignKey("photo_categories.id"))

    parent = relationship("PhotoCategory", remote_side=[id], backref="children")
    photos = relationship(
        "Photo", secondary=table_photo_category, back_populates="categories"
    )


class Tag(Base):
    __tablename__ = "tags"

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False)

    photos = relationship("Photo", secondary=table_photo_tag, back_populates="tags")
