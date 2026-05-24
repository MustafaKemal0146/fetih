#!/bin/bash
# Docker/Podman entrypoint: bootstrap config files into the mounted volume, then run fetih.
set -e

FETIH_HOME="${FETIH_HOME:-/opt/data}"
INSTALL_DIR="/opt/fetih"

# --- Privilege dropping via gosu ---
# When started as root (the default for Docker, or fakeroot in rootless Podman),
# optionally remap the fetih user/group to match host-side ownership, fix volume
# permissions, then re-exec as fetih.
if [ "$(id -u)" = "0" ]; then
    if [ -n "$FETIH_UID" ] && [ "$FETIH_UID" != "$(id -u fetih)" ]; then
        echo "Changing fetih UID to $FETIH_UID"
        usermod -u "$FETIH_UID" fetih
    fi

    if [ -n "$FETIH_GID" ] && [ "$FETIH_GID" != "$(id -g fetih)" ]; then
        echo "Changing fetih GID to $FETIH_GID"
        # -o allows non-unique GID (e.g. macOS GID 20 "staff" may already exist
        # as "dialout" in the Debian-based container image)
        groupmod -o -g "$FETIH_GID" fetih 2>/dev/null || true
    fi

    # Fix ownership of the data volume. When FETIH_UID remaps the fetih user,
    # files created by previous runs (under the old UID) become inaccessible.
    # Always chown -R when UID was remapped; otherwise only if top-level is wrong.
    actual_fetih_uid=$(id -u fetih)
    needs_chown=false
    if [ -n "$FETIH_UID" ] && [ "$FETIH_UID" != "10000" ]; then
        needs_chown=true
    elif [ "$(stat -c %u "$FETIH_HOME" 2>/dev/null)" != "$actual_fetih_uid" ]; then
        needs_chown=true
    fi
    if [ "$needs_chown" = true ]; then
        echo "Fixing ownership of $FETIH_HOME to fetih ($actual_fetih_uid)"
        # In rootless Podman the container's "root" is mapped to an unprivileged
        # host UID — chown will fail.  That's fine: the volume is already owned
        # by the mapped user on the host side.
        chown -R fetih:fetih "$FETIH_HOME" 2>/dev/null || \
            echo "Warning: chown failed (rootless container?) — continuing anyway"
        # The .venv must also be re-chowned when UID is remapped, otherwise
        # lazy_deps.py cannot install platform packages (discord.py, etc.).
        chown -R fetih:fetih "$INSTALL_DIR/.venv" 2>/dev/null || \
            echo "Warning: chown .venv failed (rootless container?) — continuing anyway"
    fi

    # Ensure config.yaml is readable by the fetih runtime user even if it was
    # edited on the host after initial ownership setup. Must run here (as root)
    # rather than after the gosu drop, otherwise a non-root caller like
    # `docker run -u $(id -u):$(id -g)` hits "Operation not permitted" (#15865).
    if [ -f "$FETIH_HOME/config.yaml" ]; then
        chown fetih:fetih "$FETIH_HOME/config.yaml" 2>/dev/null || true
        chmod 640 "$FETIH_HOME/config.yaml" 2>/dev/null || true
    fi

    echo "Dropping root privileges"
    exec gosu fetih "$0" "$@"
fi

# --- Running as fetih from here ---
source "${INSTALL_DIR}/.venv/bin/activate"

# Stamp install method for detect_install_method()
echo "docker" > "${FETIH_HOME:=/opt/data}/.install_method" 2>/dev/null || true

# Create essential directory structure.  Cache and platform directories
# (cache/images, cache/audio, platforms/whatsapp, etc.) are created on
# demand by the application — don't pre-create them here so new installs
# get the consolidated layout from get_fetih_dir().
# The "home/" subdirectory is a per-profile HOME for subprocesses (git,
# ssh, gh, npm …).  Without it those tools write to /root which is
# ephemeral and shared across profiles.  See issue #4426.
mkdir -p "$FETIH_HOME"/{cron,sessions,logs,hooks,memories,skills,skins,plans,workspace,home}

# .env
if [ ! -f "$FETIH_HOME/.env" ]; then
    cp "$INSTALL_DIR/.env.example" "$FETIH_HOME/.env"
fi

# config.yaml
if [ ! -f "$FETIH_HOME/config.yaml" ]; then
    cp "$INSTALL_DIR/cli-config.yaml.example" "$FETIH_HOME/config.yaml"
fi

# SOUL.md
if [ ! -f "$FETIH_HOME/SOUL.md" ]; then
    cp "$INSTALL_DIR/docker/SOUL.md" "$FETIH_HOME/SOUL.md"
fi

# auth.json: bootstrap from env on first boot only.  Used by orchestrators
# (e.g. provisioning a FETIH VPS from an account-management service) that
# need to seed the OAuth refresh credential non-interactively, instead of
# walking the user through `fetih setup` + the device-flow login dance.
# Subsequent token rotations write back to the same file, which lives on a
# persistent volume — so this env var is consumed exactly once at first
# boot.  The `[ ! -f ... ]` guard is critical: without it, a container
# restart would clobber a rotated refresh token with the now-stale value
# the orchestrator originally seeded.
if [ ! -f "$FETIH_HOME/auth.json" ] && [ -n "$FETIH_AUTH_JSON_BOOTSTRAP" ]; then
    printf '%s' "$FETIH_AUTH_JSON_BOOTSTRAP" > "$FETIH_HOME/auth.json"
    chmod 600 "$FETIH_HOME/auth.json"
fi

# Sync bundled skills (manifest-based so user edits are preserved)
if [ -d "$INSTALL_DIR/skills" ]; then
    python3 "$INSTALL_DIR/tools/skills_sync.py"
fi

# Optionally start `fetih dashboard` as a side-process.
#
# Toggled by FETIH_DASHBOARD=1 (also accepts "true"/"yes", case-insensitive).
# Host/port/TUI can be overridden via:
#   FETIH_DASHBOARD_HOST  (default 0.0.0.0 — exposed outside the container)
#   FETIH_DASHBOARD_PORT  (default 9119, matches `fetih dashboard` default)
#   FETIH_DASHBOARD_TUI   (already honored by `fetih dashboard` itself)
#
# The dashboard is a long-lived server.  We background it *before* the final
# `exec fetih "$@"` so the user's chosen foreground command (chat, gateway,
# sleep infinity, …) remains PID-of-interest for the container runtime.  When
# the container stops the whole process tree is torn down, so no explicit
# cleanup is needed.
case "${FETIH_DASHBOARD:-}" in
    1|true|TRUE|True|yes|YES|Yes)
        dash_host="${FETIH_DASHBOARD_HOST:-0.0.0.0}"
        dash_port="${FETIH_DASHBOARD_PORT:-9119}"
        dash_args=(--host "$dash_host" --port "$dash_port" --no-open)
        # Binding to anything other than localhost requires --insecure — the
        # dashboard refuses otherwise because it exposes API keys.  Inside a
        # container this is the expected deployment (host reaches it via
        # published port), so opt in automatically.
        if [ "$dash_host" != "127.0.0.1" ] && [ "$dash_host" != "localhost" ]; then
            dash_args+=(--insecure)
        fi
        echo "Starting fetih dashboard on ${dash_host}:${dash_port} (background)"
        # Prefix dashboard output so it's distinguishable from the main
        # process in `docker logs`.  stdbuf keeps the pipe line-buffered.
        (
            stdbuf -oL -eL fetih dashboard "${dash_args[@]}" 2>&1 \
                | sed -u 's/^/[dashboard] /'
        ) &
        ;;
esac

# Final exec: two supported invocation patterns.
#
#   docker run <image>                 -> exec `fetih` with no args (legacy default)
#   docker run <image> chat -q "..."   -> exec `fetih chat -q "..."` (legacy wrap)
#   docker run <image> sleep infinity  -> exec `sleep infinity` directly
#   docker run <image> bash            -> exec `bash` directly
#
# If the first positional arg resolves to an executable on PATH, we assume the
# caller wants to run it directly (needed by the launcher which runs long-lived
# `sleep infinity` sandbox containers — see tools/environments/docker.py).
# Otherwise we treat the args as a fetih subcommand and wrap with `fetih`,
# preserving the documented `docker run <image> <subcommand>` behavior.
if [ $# -gt 0 ] && command -v "$1" >/dev/null 2>&1; then
    exec "$@"
fi
exec fetih "$@"
