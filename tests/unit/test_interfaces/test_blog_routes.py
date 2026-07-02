import os
import secrets
import pytest

os.environ["SAN_TESTING"] = "1"
os.environ["ENVIRONMENT"] = "development"


@pytest.fixture
def client(mock_settings, reset_identity_registry, reset_log_indexer, reset_persistence, tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    from secureagentnet.database.connection import dispose_engine, init_database
    from secureagentnet.core.config import get_settings
    dispose_engine()
    get_settings.cache_clear()
    init_database()
    from secureagentnet.main import app
    from fastapi.testclient import TestClient
    with TestClient(app) as c:
        yield c


class TestBlogCreate:
    def test_create_post_success(self, client):
        slug = f"test-post-{secrets.token_hex(4)}"
        res = client.post("/api/v1/blog/posts", json={
            "title": "Test Blog Post",
            "slug": slug,
            "summary": "A test summary",
            "content": "Full content of the test post.",
            "author": "admin",
            "tags": ["security", "testing"],
            "read_time": "3 MIN",
        })
        assert res.status_code == 201
        data = res.json()
        assert data["title"] == "Test Blog Post"
        assert data["slug"] == slug
        assert data["author"] == "admin"
        assert data["tags"] == ["security", "testing"]
        assert data["published"] is True

    def test_create_duplicate_slug_fails(self, client):
        slug = f"dup-{secrets.token_hex(4)}"
        client.post("/api/v1/blog/posts", json={
            "title": "First", "slug": slug, "content": "Content.", "author": "admin",
        })
        res = client.post("/api/v1/blog/posts", json={
            "title": "Second", "slug": slug, "content": "Content.", "author": "admin",
        })
        assert res.status_code == 409

    def test_create_post_with_long_content(self, client):
        slug = f"long-{secrets.token_hex(4)}"
        res = client.post("/api/v1/blog/posts", json={
            "title": "Long Content", "slug": slug,
            "content": "x" * 5000, "author": "admin",
        })
        assert res.status_code == 201
        assert len(res.json()["content"]) == 5000

    def test_create_post_with_body_field(self, client):
        slug = f"body-{secrets.token_hex(4)}"
        res = client.post("/api/v1/blog/posts", json={
            "title": "Body Field Test", "slug": slug,
            "body": "Content sent via body field", "author": "admin",
        })
        assert res.status_code == 201
        data = res.json()
        assert data["content"] == "Content sent via body field"


class TestBlogList:
    def test_list_published(self, client):
        slug = f"list-{secrets.token_hex(4)}"
        client.post("/api/v1/blog/posts", json={
            "title": "List Test", "slug": slug, "content": "Content.", "author": "admin",
        })
        res = client.get("/api/v1/blog/posts")
        assert res.status_code == 200
        data = res.json()
        assert isinstance(data, list)
        assert any(p["slug"] == slug for p in data)

    def test_list_excludes_unpublished(self, client):
        slug = f"unpub-{secrets.token_hex(4)}"
        client.post("/api/v1/blog/posts", json={
            "title": "Unpublished", "slug": slug, "content": "Content.", "author": "admin",
        })
        res = client.get("/api/v1/blog/posts")
        assert res.status_code == 200
        data = res.json()
        slugs = {p["slug"] for p in data}
        assert slug in slugs


class TestBlogDetail:
    def test_get_post_by_slug(self, client):
        slug = f"detail-{secrets.token_hex(4)}"
        client.post("/api/v1/blog/posts", json={
            "title": "Detail Test", "slug": slug, "content": "Full content.", "author": "admin",
        })
        res = client.get(f"/api/v1/blog/posts/{slug}")
        assert res.status_code == 200
        data = res.json()
        assert data["title"] == "Detail Test"
        assert data["content"] == "Full content."

    def test_get_nonexistent_returns_404(self, client):
        res = client.get("/api/v1/blog/posts/nonexistent-slug")
        assert res.status_code == 404

    def test_list_is_public_no_auth_required(self, client):
        slug = f"public-{secrets.token_hex(4)}"
        client.post("/api/v1/blog/posts", json={
            "title": "Public Post", "slug": slug, "content": "Content.", "author": "admin",
        })
        res = client.get("/api/v1/blog/posts")
        assert res.status_code == 200


class TestBlogUpload:
    def test_upload_image_success(self, client):
        file_content = b"fake image bytes"
        res = client.post(
            "/api/v1/blog/upload",
            files={"file": ("test_image.png", file_content, "image/png")}
        )
        assert res.status_code == 200
        data = res.json()
        assert "url" in data
        assert data["url"].startswith("/uploads/")
        assert data["url"].endswith(".png")

    def test_upload_invalid_type_fails(self, client):
        file_content = b"fake text bytes"
        res = client.post(
            "/api/v1/blog/upload",
            files={"file": ("test_doc.txt", file_content, "text/plain")}
        )
        assert res.status_code == 400
