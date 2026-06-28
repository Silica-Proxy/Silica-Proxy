#!/usr/bin/env bash
# Initialise le Gitea de dev démarré par `docker compose up` :
# crée un utilisateur admin et un dépôt PUBLIC "policies" pré-rempli avec dev/gitops-repo/*.yaml
# (uniquement à la création, jamais écrasé ensuite). artifactsentry.gitops.repository-url pointe
# déjà par défaut sur ce dépôt (application.yaml), qui se clone sans authentification : `bootRun`
# fonctionne donc directement après `docker compose up`, sans étape manuelle.
# Un token d'accès est tout de même généré (dans dev/.gitea-dev-env) pour les cas où l'on veut
# pousser des modifications en ligne de commande (le push, contrairement au clone, exige une auth).
#
# Lancé automatiquement par le service "gitea-init" de compose.yaml (aucune action manuelle requise).
# Peut aussi être relancé manuellement depuis l'hôte : ./dev/gitea-init.sh
set -euo pipefail

GITEA_URL="${GITEA_URL:-http://localhost:3000}"
PUBLIC_GITEA_URL="${PUBLIC_GITEA_URL:-${GITEA_URL}}"
GITEA_USER="devops"
GITEA_PASSWORD="devops12345"
GITEA_EMAIL="devops@artifactsentry.local"
REPO_NAME="policies"
ENV_FILE="$(dirname "$0")/.gitea-dev-env"

cd "$(dirname "$0")"

echo "Attente de la disponibilité de Gitea sur ${GITEA_URL}..."
until curl -sf "${GITEA_URL}/api/v1/version" > /dev/null; do
  sleep 1
done

echo "Recherche du conteneur gitea..."
until GITEA_CID=$(docker ps -q --filter "label=com.docker.compose.service=gitea" | head -1) && [ -n "${GITEA_CID}" ]; do
  sleep 1
done

if ! docker exec -u git "${GITEA_CID}" gitea admin user list | grep -q "${GITEA_USER}"; then
  echo "Création de l'utilisateur admin ${GITEA_USER}..."
  docker exec -u git "${GITEA_CID}" gitea admin user create \
    --username "${GITEA_USER}" --password "${GITEA_PASSWORD}" \
    --email "${GITEA_EMAIL}" --admin --must-change-password=false
else
  echo "Utilisateur ${GITEA_USER} déjà présent, on continue."
fi

if ! curl -sf -u "${GITEA_USER}:${GITEA_PASSWORD}" "${GITEA_URL}/api/v1/repos/${GITEA_USER}/${REPO_NAME}" > /dev/null; then
  echo "Création du dépôt ${REPO_NAME}..."
  curl -sf -u "${GITEA_USER}:${GITEA_PASSWORD}" -X POST "${GITEA_URL}/api/v1/user/repos" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"${REPO_NAME}\",\"private\":false,\"auto_init\":false}" > /dev/null

  # Premier provisionnement uniquement : on pousse le contenu de dev/gitops-repo comme point
  # de départ. Les exécutions suivantes ne touchent plus au contenu du dépôt, pour ne jamais
  # écraser des modifications faites depuis (UI Gitea ou push manuel).
  echo "Poussée des fichiers de policies initiaux (dev/gitops-repo)..."
  WORKDIR="$(mktemp -d)"
  cp gitops-repo/*.yaml "${WORKDIR}/"
  git -C "${WORKDIR}" init -q -b main
  git -C "${WORKDIR}" add .
  git -C "${WORKDIR}" -c user.email="${GITEA_EMAIL}" -c user.name="${GITEA_USER}" commit -q -m "Politiques GitOps de dev"
  REPO_PUSH_URL=$(echo "${GITEA_URL}" | sed -E "s#^(https?)://#\1://${GITEA_USER}:${GITEA_PASSWORD}@#")
  git -C "${WORKDIR}" push -q "${REPO_PUSH_URL}/${GITEA_USER}/${REPO_NAME}.git" main
  rm -rf "${WORKDIR}"
else
  echo "Dépôt ${REPO_NAME} déjà présent, on ne touche pas à son contenu."
fi

if [ -f "${ENV_FILE}" ] && grep -q ARTIFACTSENTRY_GITOPS_CLONE_TOKEN "${ENV_FILE}"; then
  echo "Token déjà généré précédemment, réutilisation de ${ENV_FILE}."
else
  echo "Génération d'un token d'accès..."
  TOKEN_JSON=$(curl -sf -u "${GITEA_USER}:${GITEA_PASSWORD}" -X POST "${GITEA_URL}/api/v1/users/${GITEA_USER}/tokens" \
    -H "Content-Type: application/json" \
    -d '{"name":"artifactsentry-dev","scopes":["write:repository","read:repository"]}')
  TOKEN=$(echo "${TOKEN_JSON}" | sed -n 's/.*"sha1":"\([^"]*\)".*/\1/p')

  cat > "${ENV_FILE}" <<EOF
export ARTIFACTSENTRY_GITOPS_REPOSITORY_URL=${PUBLIC_GITEA_URL}/${GITEA_USER}/${REPO_NAME}.git
export ARTIFACTSENTRY_GITOPS_CLONE_TOKEN=${TOKEN}
EOF
fi

echo ""
echo "Gitea de dev prêt : ${PUBLIC_GITEA_URL}/${GITEA_USER}/${REPO_NAME} (login: ${GITEA_USER} / ${GITEA_PASSWORD})"
echo "application.yaml pointe déjà sur ce dépôt par défaut : ./gradlew bootRun fonctionne directement."
echo "Pour pousser des modifications en ligne de commande (le push exige une authentification) :"
echo ""
echo "  source dev/.gitea-dev-env"
echo "  git clone http://\${ARTIFACTSENTRY_GITOPS_CLONE_TOKEN}:@localhost:3000/${GITEA_USER}/${REPO_NAME}.git"
