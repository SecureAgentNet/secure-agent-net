import hashlib
import logging
import os
import secrets
import uuid
from datetime import datetime, timezone

import shutil
from pathlib import Path

from fastapi import FastAPI, HTTPException, Depends, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from sqlalchemy import create_engine, Column, String, Text, Boolean, DateTime, JSON, Uuid
from sqlalchemy.orm import sessionmaker, declarative_base, Session

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("blog-server")

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./blog.db")
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")

Base = declarative_base()


class BlogPost(Base):
    __tablename__ = "blog_posts"
    post_id = Column(Uuid, primary_key=True, default=uuid.uuid4)
    title = Column(String(255), nullable=False)
    slug = Column(String(255), unique=True, nullable=False)
    summary = Column(Text, nullable=True)
    content = Column(Text, nullable=False)
    author = Column(String(100), nullable=False)
    tags = Column(JSON, default=[])
    read_time = Column(String(20), default="5 MIN")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    published = Column(Boolean, default=True)


if DATABASE_URL and DATABASE_URL.startswith("postgresql"):
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)
else:
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

app = FastAPI(title="SAN Blog API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


class CreatePostRequest(BaseModel):
    title: str
    slug: str
    summary: Optional[str] = None
    content: Optional[str] = None
    body: Optional[str] = None
    author: str
    tags: list[str] = []
    read_time: str = "5 MIN"

    def get_content(self) -> str:
        return self.content or self.body or ""


class LoginRequest(BaseModel):
    username: str
    password: str


def _serialize(p: BlogPost) -> dict:
    return {
        "post_id": str(p.post_id),
        "title": p.title,
        "slug": p.slug,
        "summary": p.summary,
        "content": p.content,
        "author": p.author,
        "tags": p.tags or [],
        "read_time": p.read_time or "5 MIN",
        "created_at": p.created_at.isoformat() if p.created_at else "",
        "published": bool(p.published),
    }


@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created.")


@app.get("/health")
def health():
    return {"status": "ok", "service": "SAN Blog API"}


@app.post("/api/v1/auth/operator-login")
def operator_login(body: LoginRequest):
    pw_hash = hashlib.sha256(body.password.encode()).hexdigest()
    stored_hash = hashlib.sha256(ADMIN_PASSWORD.encode()).hexdigest()
    if body.username != "admin" or pw_hash != stored_hash:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = f"san_{secrets.token_hex(32)}"
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {"user_id": "admin", "username": body.username, "role": "admin"},
    }


@app.post("/api/v1/blog/posts", status_code=201)
def create_post(body: CreatePostRequest, db: Session = Depends(get_db)):
    existing = db.query(BlogPost).filter(BlogPost.slug == body.slug).first()
    if existing:
        raise HTTPException(status_code=409, detail="A post with this slug already exists")
    post = BlogPost(
        post_id=uuid.uuid4(),
        title=body.title,
        slug=body.slug,
        summary=body.summary,
        content=body.get_content(),
        author=body.author,
        tags=body.tags,
        read_time=body.read_time,
    )
    db.add(post)
    db.commit()
    db.refresh(post)
    return _serialize(post)


@app.get("/api/v1/blog/posts")
def list_posts(db: Session = Depends(get_db)):
    posts = db.query(BlogPost).filter(BlogPost.published == True).order_by(BlogPost.created_at.desc()).all()
    return [_serialize(p) for p in posts]


@app.get("/api/v1/blog/posts/{slug}")
def get_post(slug: str, db: Session = Depends(get_db)):
    post = db.query(BlogPost).filter(BlogPost.slug == slug, BlogPost.published == True).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    return _serialize(post)


@app.post("/api/v1/blog/upload")
def upload_image(file: UploadFile = File(...)):
    if not file.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="Only image uploads are allowed")
    ext = os.path.splitext(file.filename)[1] if file.filename else ""
    if not ext or ext.lower() not in [".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg"]:
        ext = ".png"
    filename = f"{uuid.uuid4()}{ext}"
    uploads_dir = Path("uploads")
    uploads_dir.mkdir(parents=True, exist_ok=True)
    file_path = uploads_dir / filename
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    return {"url": f"/uploads/{filename}"}
