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
    echo "  --env-file FILE       Path to .env file (default: ../.env)"
    echo "  --tag TAG             Docker image tag (default: latest)"
    echo "  --registry REGISTRY   Container registry URL (default: docker.io)"
    echo "  --mode MODE           Deployment mode: docker|k8s (default: docker)"
    echo "  --kube-config FILE    Path to kubeconfig (default: ~/.kube/config)"
    echo "  -h, --help            Show this help message"
    exit 0
}

ENV_FILE="$PROJECT_DIR/.env"
IMAGE_TAG="latest"
REGISTRY=""
DEPLOY_MODE="docker"
KUBE_CONFIG=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --env-file)     ENV_FILE="$2"; shift 2 ;;
        --tag)          IMAGE_TAG="$2"; shift 2 ;;
        --registry)     REGISTRY="$2"; shift 2 ;;
        --mode)         DEPLOY_MODE="$2"; shift 2 ;;
        --kube-config)  KUBE_CONFIG="$2"; shift 2 ;;
        -h|--help)      usage ;;
        *)              log_error "Unknown option: $1"; usage ;;
    esac
done

if [ ! -f "$ENV_FILE" ]; then
    log_error "Environment file not found: $ENV_FILE"
    exit 1
fi

source "$ENV_FILE"

IMAGE_NAME="${REGISTRY:+$REGISTRY/}secureagentnet/app:${IMAGE_TAG}"

echo ""
echo -e "${CYAN}=========================================${NC}"
echo -e "${CYAN}  SecureAgentNet - Production Deploy    ${NC}"
echo -e "${CYAN}=========================================${NC}"
echo ""
log_info "Mode:      ${DEPLOY_MODE}"
log_info "Image:     ${IMAGE_NAME}"
log_info "Tag:       ${IMAGE_TAG}"
echo ""

# ------------------------------------------------------------------
# Step 1: Validate environment
# ------------------------------------------------------------------
log_info "Validating environment..."

command -v docker >/dev/null 2>&1 || { log_error "docker not found"; exit 1; }

if [ "$DEPLOY_MODE" = "k8s" ]; then
    command -v kubectl >/dev/null 2>&1 || { log_error "kubectl not found"; exit 1; }
    command -v kustomize >/dev/null 2>&1 || log_warn "kustomize not found. Using raw kubectl."
fi

log_ok "Environment validation passed."

# ------------------------------------------------------------------
# Step 2: Build Docker image
# ------------------------------------------------------------------
log_info "Building Docker image..."
docker build \
    -t "$IMAGE_NAME" \
    -f "$PROJECT_DIR/deployment/docker/Dockerfile" \
    "$PROJECT_DIR"
log_ok "Docker image built: ${IMAGE_NAME}"

# ------------------------------------------------------------------
# Step 3: Push to registry
# ------------------------------------------------------------------
if [ -n "$REGISTRY" ]; then
    log_info "Pushing image to registry..."
    docker push "$IMAGE_NAME"
    log_ok "Image pushed: ${IMAGE_NAME}"
else
    log_warn "No registry configured. Skipping image push."
fi

# ------------------------------------------------------------------
# Step 4: Deploy
# ------------------------------------------------------------------
cd "$PROJECT_DIR/deployment"

case "$DEPLOY_MODE" in
    docker)
        log_info "Deploying with Docker Compose..."
        export IMAGE_TAG
        docker stack deploy -c docker-compose.prod.yml securenet --with-registry-auth || \
        docker compose -f docker-compose.prod.yml up -d
        log_ok "Docker deployment complete."
        ;;

    k8s)
        log_info "Deploying to Kubernetes..."

        KUBECTL_ARGS=""
        if [ -n "$KUBE_CONFIG" ]; then
            KUBECTL_ARGS="--kubeconfig=${KUBE_CONFIG}"
        fi

        kubectl $KUBECTL_ARGS apply -f kubernetes/configmap.yaml
        kubectl $KUBECTL_ARGS apply -f kubernetes/deployment.yaml
        kubectl $KUBECTL_ARGS apply -f kubernetes/service.yaml

        log_ok "Kubernetes manifests applied."
        ;;

    *)
        log_error "Unknown deploy mode: ${DEPLOY_MODE}"
        exit 1
        ;;
esac

# ------------------------------------------------------------------
# Step 5: Health-check loop
# ------------------------------------------------------------------
log_info "Running health-check loop..."
MAX_RETRIES=30
RETRY_INTERVAL=10

for i in $(seq 1 "$MAX_RETRIES"); do
    case "$DEPLOY_MODE" in
        docker)
            if docker ps --filter "name=securenet-app" --format "{{.Status}}" | grep -q "Up"; then
                HEALTH=$(docker exec securenet-app curl -sf http://localhost:5000/health 2>/dev/null || echo "")
                if [ -n "$HEALTH" ]; then
                    log_ok "Application is healthy: ${HEALTH}"
                    break
                fi
            fi
            ;;
        k8s)
            READY=$(kubectl $KUBECTL_ARGS get pods -l app=securenet-app -o jsonpath='{.items[0].status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "False")
            if [ "$READY" = "True" ]; then
                log_ok "Kubernetes pods are ready."
                break
            fi
            ;;
    esac

    if [ "$i" -eq "$MAX_RETRIES" ]; then
        log_error "Health-check failed after ${MAX_RETRIES} attempts."
        exit 1
    fi
    sleep "$RETRY_INTERVAL"
done

echo ""
echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}  SecureAgentNet deployed successfully!  ${NC}"
echo -e "${GREEN}=========================================${NC}"
echo ""

cd "$PROJECT_DIR"
