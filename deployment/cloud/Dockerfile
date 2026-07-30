# SecureAgentNet Cloud Console backend image.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install only what the cloud backend needs (the gateway's heavy deps such as
# presidio/spacy/docker are not required to aggregate metadata).
COPY pyproject.toml ./
COPY secureagentnet ./secureagentnet
RUN pip install --upgrade pip \
    && pip install fastapi "uvicorn[standard]" sqlalchemy alembic psycopg2-binary \
       pydantic pydantic-settings "passlib[bcrypt]" PyJWT

EXPOSE 8800

# On startup the app runs `alembic upgrade head` (via init_db) before serving, so
# an in-place upgrade of an existing DB gains new columns/tables. To run the
# migration as a discrete pre-deploy step instead, exec:
#   docker compose run --rm cloud-console python -m secureagentnet.cloud --migrate
# SAN_CLOUD_DATABASE_URL (postgres), SAN_CLOUD_SECRET_KEY, SAN_CLOUD_ADMIN_* via env.
CMD ["python", "-m", "secureagentnet.cloud", "--host", "0.0.0.0", "--port", "8800"]
