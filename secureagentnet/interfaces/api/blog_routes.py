import logging
import uuid
from datetime import datetime, timezone

import os
import shutil
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, File, UploadFile
from pydantic import BaseModel, ConfigDict
from typing import Optional

from secureagentnet.database.connection import get_db_session
from secureagentnet.database.models import BlogPost
from secureagentnet.interfaces.api.auth import get_current_operator

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/blog", tags=["Blog"])


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


class BlogPostResponse(BaseModel):
    post_id: str
    title: str
    slug: str
    summary: Optional[str] = None
    content: str
    author: str
    tags: list
    read_time: str
    created_at: str
    published: bool

    model_config = ConfigDict(from_attributes=True)


def _serialize_post(p: BlogPost) -> dict:
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


@router.post("/posts", response_model=BlogPostResponse, status_code=201)
def create_post(body: CreatePostRequest, _operator: dict = Depends(get_current_operator)):
    with get_db_session() as session:
        existing = session.query(BlogPost).filter(BlogPost.slug == body.slug).first()
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
        session.add(post)
        session.commit()
        session.refresh(post)
        logger.info("Published blog post: %s", body.slug)
        return _serialize_post(post)


@router.get("/posts", response_model=list[BlogPostResponse])
def list_posts():
    with get_db_session() as session:
        posts = session.query(BlogPost).filter(BlogPost.published == True).order_by(BlogPost.created_at.desc()).all()
        return [_serialize_post(p) for p in posts]


@router.get("/posts/{slug}", response_model=BlogPostResponse)
def get_post(slug: str):
    with get_db_session() as session:
        post = session.query(BlogPost).filter(BlogPost.slug == slug, BlogPost.published == True).first()
        if not post:
            raise HTTPException(status_code=404, detail="Post not found")
        return _serialize_post(post)


@router.post("/upload")
def upload_image(file: UploadFile = File(...), _operator: dict = Depends(get_current_operator)):
    if not file.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="Only image uploads are allowed")

    ext = os.path.splitext(file.filename)[1] if file.filename else ""
    if not ext or ext.lower() not in [".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg"]:
        ext = ".png"

    filename = f"{uuid.uuid4()}{ext}"
    uploads_dir = Path(__file__).parent.parent.parent.parent / "uploads"
    uploads_dir.mkdir(parents=True, exist_ok=True)

    file_path = uploads_dir / filename
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    logger.info("Uploaded image saved to: %s", file_path)
    return {"url": f"/uploads/{filename}"}
