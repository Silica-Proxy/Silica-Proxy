#!/usr/bin/env bash
# Provisions the development Gitea started by `docker compose up`:
# creates an admin user and a PUBLIC "policies" repository seeded with dev/gitops-repo/*.yaml
# (on creation only, never overwritten afterwards). silicaproxy.gitops.repository-url already
# points at this repository by default (application.yaml), and it can be cloned without
# authentication: `./gradlew bootRun` works right after `docker compose up`, with no manual step.
# An access token is still generated (in dev/.gitea-dev-env) to push changes from the command
# line (unlike a clone, a push requires authentication).
#
# Run automatically by the "gitea-init" service of compose.yaml (no manual action needed).
# Can also be run again from the host: ./dev/gitea-init.sh
set -euo pipefail

GITEA_URL="${GITEA_URL:-http://localhost:3000}"
PUBLIC_GITEA_URL="${PUBLIC_GITEA_URL:-${GITEA_URL}}"
GITEA_USER="devops"
GITEA_PASSWORD="devops12345"
GITEA_EMAIL="devops@silicaproxy.local"
REPO_NAME="policies"
TOKEN_NAME="silicaproxy-dev"
# Absolute: the script changes directory below, and may be run from anywhere
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.gitea-dev-env"

cd "${SCRIPT_DIR}"

echo "Waiting for Gitea at ${GITEA_URL}..."
until curl -sf "${GITEA_URL}/api/v1/version" > /dev/null; do
  sleep 1
done

echo "Looking for the gitea container..."
until GITEA_CID=$(docker ps -q --filter "label=com.docker.compose.service=gitea" | head -1) && [ -n "${GITEA_CID}" ]; do
  sleep 1
done

if ! docker exec -u git "${GITEA_CID}" gitea admin user list | grep -q "${GITEA_USER}"; then
  echo "Creating admin user ${GITEA_USER}..."
  docker exec -u git "${GITEA_CID}" gitea admin user create \
    --username "${GITEA_USER}" --password "${GITEA_PASSWORD}" \
    --email "${GITEA_EMAIL}" --admin --must-change-password=false
else
  echo "User ${GITEA_USER} already exists, continuing."
fi

if ! curl -sf -u "${GITEA_USER}:${GITEA_PASSWORD}" "${GITEA_URL}/api/v1/repos/${GITEA_USER}/${REPO_NAME}" > /dev/null; then
  echo "Creating repository ${REPO_NAME}..."
  curl -sf -u "${GITEA_USER}:${GITEA_PASSWORD}" -X POST "${GITEA_URL}/api/v1/user/repos" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"${REPO_NAME}\",\"private\":false,\"auto_init\":false}" > /dev/null

  # First provisioning only: push the content of dev/gitops-repo as a starting point. Later runs
  # never touch the repository content, so changes made since (Gitea UI or manual push) are kept.
  echo "Pushing the initial policy files (dev/gitops-repo)..."
  WORKDIR="$(mktemp -d)"
  cp gitops-repo/*.yaml "${WORKDIR}/"
  git -C "${WORKDIR}" init -q -b main
  git -C "${WORKDIR}" add .
  git -C "${WORKDIR}" -c user.email="${GITEA_EMAIL}" -c user.name="${GITEA_USER}" commit -q -m "Development GitOps policies"
  REPO_PUSH_URL=$(echo "${GITEA_URL}" | sed -E "s#^(https?)://#\1://${GITEA_USER}:${GITEA_PASSWORD}@#")
  git -C "${WORKDIR}" push -q "${REPO_PUSH_URL}/${GITEA_USER}/${REPO_NAME}.git" main
  rm -rf "${WORKDIR}"
else
  echo "Repository ${REPO_NAME} already exists, leaving its content untouched."
fi

if [ -f "${ENV_FILE}" ] && grep -q SILICAPROXY_GITOPS_CLONE_TOKEN "${ENV_FILE}"; then
  echo "Token already generated, reusing ${ENV_FILE}."
else
  echo "Generating an access token..."
  # Gitea rejects a second token with the same name: drop a previous one (e.g. after
  # ${ENV_FILE} was deleted) before creating it again.
  curl -s -o /dev/null -u "${GITEA_USER}:${GITEA_PASSWORD}" -X DELETE \
    "${GITEA_URL}/api/v1/users/${GITEA_USER}/tokens/${TOKEN_NAME}" || true
  TOKEN_JSON=$(curl -sf -u "${GITEA_USER}:${GITEA_PASSWORD}" -X POST "${GITEA_URL}/api/v1/users/${GITEA_USER}/tokens" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"${TOKEN_NAME}\",\"scopes\":[\"write:repository\",\"read:repository\"]}")
  TOKEN=$(echo "${TOKEN_JSON}" | sed -n 's/.*"sha1":"\([^"]*\)".*/\1/p')

  cat > "${ENV_FILE}" <<EOF
export SILICAPROXY_GITOPS_REPOSITORY_URL=${PUBLIC_GITEA_URL}/${GITEA_USER}/${REPO_NAME}.git
export SILICAPROXY_GITOPS_CLONE_TOKEN=${TOKEN}
EOF
fi

echo ""
echo "Development Gitea ready: ${PUBLIC_GITEA_URL}/${GITEA_USER}/${REPO_NAME} (login: ${GITEA_USER} / ${GITEA_PASSWORD})"
echo "application.yaml already points at this repository: ./gradlew bootRun works as is."
echo "To push changes from the command line (a push requires authentication):"
echo ""
echo "  source dev/.gitea-dev-env"
echo "  git clone http://\${SILICAPROXY_GITOPS_CLONE_TOKEN}:@localhost:3000/${GITEA_USER}/${REPO_NAME}.git"
