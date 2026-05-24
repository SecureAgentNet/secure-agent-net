#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${CYAN}[INFO]${NC}  $1"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}    $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --s3-bucket BUCKET     S3-compatible bucket name (required)"
    echo "  --s3-endpoint URL      S3 endpoint (default: https://s3.amazonaws.com)"
    echo "  --s3-region REGION     S3 region (default: us-east-1)"
    echo "  --pg-dump-path PATH    pg_dump binary path (default: pg_dump)"
    echo "  --backup-dir DIR       Local backup directory (default: /tmp/securenet-backups)"
    echo "  --retention-days N     Retention days for local backups (default: 7)"
    echo "  -h, --help             Show this help message"
    exit 0
}

S3_BUCKET=""
S3_ENDPOINT="https://s3.amazonaws.com"
S3_REGION="us-east-1"
PG_DUMP_PATH="pg_dump"
BACKUP_DIR="/tmp/securenet-backups"
RETENTION_DAYS=7

while [[ $# -gt 0 ]]; do
    case "$1" in
        --s3-bucket)      S3_BUCKET="$2"; shift 2 ;;
        --s3-endpoint)    S3_ENDPOINT="$2"; shift 2 ;;
        --s3-region)      S3_REGION="$2"; shift 2 ;;
        --pg-dump-path)   PG_DUMP_PATH="$2"; shift 2 ;;
        --backup-dir)     BACKUP_DIR="$2"; shift 2 ;;
        --retention-days) RETENTION_DAYS="$2"; shift 2 ;;
        -h|--help)        usage ;;
        *)                log_error "Unknown option: $1"; usage ;;
    esac
done

if [ -z "${S3_BUCKET}" ]; then
    log_error "--s3-bucket is required."
    exit 1
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_PATH="${BACKUP_DIR}/${TIMESTAMP}"
DB_DUMP_FILE="${BACKUP_PATH}/securenet_db.sql.gz"
VAULT_SNAPSHOT_FILE="${BACKUP_PATH}/vault_raft.snap"
LOGS_TARBALL="${BACKUP_PATH}/logs.tar.gz"

mkdir -p "$BACKUP_PATH"

echo ""
echo -e "${CYAN}=========================================${NC}"
echo -e "${CYAN}  SecureAgentNet - Backup ${TIMESTAMP}    ${NC}"
echo -e "${CYAN}=========================================${NC}"
echo ""

# ------------------------------------------------------------------
# 1. PostgreSQL Dump
# ------------------------------------------------------------------
log_info "Dumping PostgreSQL database..."

DB_CONTAINER="securenet-postgres"
DB_USER="${POSTGRES_USER:-secureagent}"
DB_NAME="securenet_db"

if docker ps --filter "name=${DB_CONTAINER}" --format "{{.Names}}" | grep -q "${DB_CONTAINER}"; then
    docker exec "${DB_CONTAINER}" pg_dump -U "${DB_USER}" "${DB_NAME}" | gzip > "${DB_DUMP_FILE}"
    log_ok "Database dump saved: ${DB_DUMP_FILE} ($(du -h "${DB_DUMP_FILE}" | cut -f1))"
else
    log_warn "PostgreSQL container not running. Attempting direct pg_dump..."
    ${PG_DUMP_PATH} -U "${DB_USER}" -h localhost "${DB_NAME}" | gzip > "${DB_DUMP_FILE}" || {
        log_error "pg_dump failed. Skipping database backup."
        rm -f "${DB_DUMP_FILE}"
    }
fi

# ------------------------------------------------------------------
# 2. Vault Raft Snapshot
# ------------------------------------------------------------------
log_info "Taking Vault Raft snapshot..."

VAULT_CONTAINER="securenet-vault"
VAULT_TOKEN="${VAULT_TOKEN:-root}"

if docker ps --filter "name=${VAULT_CONTAINER}" --format "{{.Names}}" | grep -q "${VAULT_CONTAINER}"; then
    docker exec \
        -e VAULT_TOKEN="${VAULT_TOKEN}" \
        "${VAULT_CONTAINER}" \
        vault operator raft snapshot save "/tmp/vault_snapshot.snap" >/dev/null 2>&1 && \
    docker cp "${VAULT_CONTAINER}:/tmp/vault_snapshot.snap" "${VAULT_SNAPSHOT_FILE}" && \
    docker exec "${VAULT_CONTAINER}" rm -f /tmp/vault_snapshot.snap
    log_ok "Vault snapshot saved: ${VAULT_SNAPSHOT_FILE} ($(du -h "${VAULT_SNAPSHOT_FILE}" | cut -f1))"
else
    log_warn "Vault container not running. Skipping Raft snapshot."
fi

# ------------------------------------------------------------------
# 3. Compress Log Files
# ------------------------------------------------------------------
log_info "Archiving log files..."

LOG_DIRS=(
    "$PROJECT_DIR/logs"
    "$PROJECT_DIR/data/logs"
)

for dir in "${LOG_DIRS[@]}"; do
    if [ -d "$dir" ] && [ "$(find "$dir" -type f 2>/dev/null | wc -l)" -gt 0 ]; then
        tar -czf "$LOGS_TARBALL" -C "$(dirname "$dir")" "$(basename "$dir")" 2>/dev/null || true
    fi
done

if [ -f "$LOGS_TARBALL" ]; then
    log_ok "Logs archived: ${LOGS_TARBALL} ($(du -h "${LOGS_TARBALL}" | cut -f1))"
else
    log_warn "No log files found to archive."
    rm -f "$LOGS_TARBALL"
fi

# ------------------------------------------------------------------
# 4. Upload to S3-Compatible Storage
# ------------------------------------------------------------------
log_info "Uploading backup to S3-compatible storage..."

S3_TARGET="s3://${S3_BUCKET}/securenet-backups/${TIMESTAMP}/"

if command -v aws &>/dev/null; then
    aws s3 sync \
        --endpoint-url "${S3_ENDPOINT}" \
        --region "${S3_REGION}" \
        "${BACKUP_PATH}" \
        "${S3_TARGET}"
    log_ok "Backup uploaded to ${S3_TARGET}"
elif command -v s3cmd &>/dev/null; then
    s3cmd sync \
        --host="${S3_ENDPOINT}" \
        --region="${S3_REGION}" \
        "${BACKUP_PATH}/" \
        "s3://${S3_BUCKET}/securenet-backups/${TIMESTAMP}/"
    log_ok "Backup uploaded via s3cmd."
elif command -v mc &>/dev/null; then
    mc alias set target "${S3_ENDPOINT}" "${AWS_ACCESS_KEY_ID}" "${AWS_SECRET_ACCESS_KEY}"
    mc cp --recursive "${BACKUP_PATH}/" "target/${S3_BUCKET}/securenet-backups/${TIMESTAMP}/"
    log_ok "Backup uploaded via mc (minio client)."
else
    curl_w_upload() {
        local file="$1"
        local key="securenet-backups/${TIMESTAMP}/$(basename "$file")"
        curl -sf -X PUT \
            "${S3_ENDPOINT}/${S3_BUCKET}/${key}" \
            --data-binary "@${file}" \
            -H "Content-Type: application/octet-stream" \
            -H "x-amz-acl: private" \
            2>/dev/null || return 1
    }

    UPLOAD_OK=true
    for f in "$BACKUP_PATH"/*; do
        [ -f "$f" ] || continue
        curl_w_upload "$f" || { UPLOAD_OK=false; break; }
    done

    if [ "$UPLOAD_OK" = true ]; then
        log_ok "Backup uploaded via curl (direct S3 PUT)."
    else
        log_warn "Failed to upload via curl. Please install awscli, s3cmd, or minio-client."
    fi
fi

# ------------------------------------------------------------------
# 5. Cleanup old local backups
# ------------------------------------------------------------------
log_info "Cleaning up backups older than ${RETENTION_DAYS} days..."

find "${BACKUP_DIR}" -mindepth 1 -maxdepth 1 -type d -mtime "+${RETENTION_DAYS}" \
    -exec rm -rf {} \; \
    -exec log_info "Removed old backup: {}" \;

log_ok "Local backup retention cleanup complete."

# ===== Generate backup manifest =====
cat > "${BACKUP_PATH}/manifest.txt" <<EOF
Backup Timestamp: ${TIMESTAMP}
Database:         ${DB_DUMP_FILE}
Vault Snapshot:   ${VAULT_SNAPSHOT_FILE}
Logs Archive:     ${LOGS_TARBALL}
S3 Bucket:        ${S3_BUCKET}
S3 Path:          securenet-backups/${TIMESTAMP}/
EOF

echo ""
echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}  Backup completed successfully!         ${NC}"
echo -e "${GREEN}=========================================${NC}"
echo ""
log_info "Local backup:  ${BACKUP_PATH}"
log_info "S3 destination: ${S3_TARGET}"
echo ""
