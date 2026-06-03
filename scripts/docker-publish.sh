#!/usr/bin/env bash
# Build + push the goliakk/gnet Docker image.
#
# Scope: this script alone — no GitHub Actions, no auto-trigger. Run
# manually when you actually want to publish a new image (typically
# right after a `gnet-v*` tag lands). Strictly separate from product
# CI (.github/workflows/ci.yml) and from fleet deploy
# (scripts/deploy-fleet.sh).
#
# One-time setup:
#   docker login -u goliakk
#   (paste Docker Hub PAT when prompted; credentials persist in
#    ~/.docker/config.json — never put the PAT in this repo)
#
# Usage:
#   scripts/docker-publish.sh <version>
#   scripts/docker-publish.sh 1.0.0
#   scripts/docker-publish.sh 1.0.0 --also-latest    # also tag :latest
#
# What it does:
#   1. Verifies the working tree matches a clean tag (warns if not).
#   2. docker build -t goliakk/gnet:<version>
#   3. docker push goliakk/gnet:<version>
#   4. Optionally retag + push :latest.
#
# Multi-arch: this script builds for the host arch only. For
# linux/amd64 + linux/arm64 multi-arch images, use buildx — left as a
# follow-up since the v1.0.0 audience is Linux x86_64.

set -euo pipefail

IMAGE=${IMAGE:-goliakk/gnet}

if [ $# -lt 1 ]; then
    cat <<EOF >&2
Usage: $0 <version> [--also-latest]

Examples:
  $0 1.0.0
  $0 1.0.0 --also-latest

The image is pushed as ${IMAGE}:<version>.
EOF
    exit 2
fi

VERSION=$1
ALSO_LATEST=${2:-}

# warn (don't block) on dirty / off-tag tree — we still let the
# operator publish a "snapshot" image deliberately if they want
if ! git diff --quiet HEAD; then
    echo "!! working tree is dirty — image will not match any tag" >&2
fi
TAG_AT_HEAD=$(git tag --points-at HEAD | head -1 || true)
if [ -z "$TAG_AT_HEAD" ]; then
    echo "!! HEAD has no git tag — published image is a snapshot" >&2
elif [ "$TAG_AT_HEAD" != "gnet-v${VERSION}" ]; then
    echo "!! HEAD tag is '$TAG_AT_HEAD' but you're publishing as ${VERSION}" >&2
fi

# verify docker login carried through to ~/.docker/config.json
if ! grep -q "index.docker.io" ~/.docker/config.json 2>/dev/null; then
    echo "!! no docker login state — run: docker login -u goliakk" >&2
    exit 1
fi

echo "==> building ${IMAGE}:${VERSION}"
docker build -t "${IMAGE}:${VERSION}" .

echo "==> pushing ${IMAGE}:${VERSION}"
docker push "${IMAGE}:${VERSION}"

if [ "$ALSO_LATEST" = "--also-latest" ]; then
    echo "==> retagging + pushing ${IMAGE}:latest"
    docker tag "${IMAGE}:${VERSION}" "${IMAGE}:latest"
    docker push "${IMAGE}:latest"
fi

echo
echo "✓ published ${IMAGE}:${VERSION}"
[ "$ALSO_LATEST" = "--also-latest" ] && echo "✓ retagged   ${IMAGE}:latest"
echo "  inspect: https://hub.docker.com/r/${IMAGE}/tags"
