#
# Builder image
#

# Base images pinned by digest: a tag can be moved to other content, a digest
# cannot. Bump tag and digest together (Dependabot's docker ecosystem does both).
FROM ghcr.io/astral-sh/uv:0.11.27@sha256:4d01caf3b22dfd11003455e2e68153da08c4ee1fa54fdbd166c6282d22693419 AS uv

# Python version for vea-challenger (matches .python-version)
FROM python:3.15.1-alpine3.24@sha256:54448f67d7c31c39e5cdd3ea2d6382395ce142806c284425f8e897d78a0465b3 AS builder

COPY --from=uv /uv /uvx /usr/local/bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app

# Dependency layer, cached independently of source changes
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,id=uv-cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project

# Source code copy step
COPY src ./src
COPY README.md ./

# Install the project itself into the venv as a regular (non-editable) package,
# so the runtime image needs only the venv, not the source tree
RUN --mount=type=cache,id=uv-cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable


# ----------------------------------------------------------------------------------------------------
# ----------------------------------------------------------------------------------------------------
# ----------------------------------------------------------------------------------------------------


#
# Deployable image
#
# This is the final layer that will be deployed and run

FROM python:3.15.1-alpine3.24@sha256:54448f67d7c31c39e5cdd3ea2d6382395ce142806c284425f8e897d78a0465b3 AS vea-challenger

# Fixed uid/gid (not -S/system range) so a host-side `chown 1000:1000` on a
# bind-mounted ./data works the same on every host.
RUN addgroup -g 1000 app && adduser -D -u 1000 -G app app \
    && mkdir -p /data && chown -R app:app /data

# Copy only the built venv from the builder (same absolute path as the builder
# stage: the venv's shebangs are baked with this path at build time). Owned by
# root, so the bot cannot rewrite its own code.
COPY --from=builder /app/.venv /app/.venv

USER app
WORKDIR /app

ENV PATH="/app/.venv/bin:${PATH}" \
    VEA_DB_PATH=/data/vea-challenger.db

ENTRYPOINT ["vea-challenger"]
CMD ["run"]
