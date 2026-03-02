#!/usr/bin/env bash
# Setup script for Aperture + OpenClaw demo.
# Creates an isolated workspace with a fresh DB and fast-learning thresholds.
#
# Usage:
#   bash examples/openclaw_setup.sh
#   cd /tmp/aperture-openclaw-demo && openclaw chat
set -euo pipefail

DEMO_DIR="/tmp/aperture-openclaw-demo"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── 1. Check prerequisites ──────────────────────────────────────────
if ! command -v openclaw >/dev/null 2>&1; then
    echo "ERROR: OpenClaw (ClawDBot) not found."
    echo "Install it:  npm install -g openclaw@latest"
    exit 1
fi

if ! command -v aperture >/dev/null 2>&1; then
    echo "ERROR: Aperture CLI not found."
    echo "Install it:  cd aperture && pip install -e ."
    exit 1
fi

# ── 2. Create isolated workspace ────────────────────────────────────
echo "Creating demo workspace at $DEMO_DIR ..."
rm -rf "$DEMO_DIR"
mkdir -p "$DEMO_DIR"

# ── 3. Copy config files ────────────────────────────────────────────
cp "$SCRIPT_DIR/openclaw.json" "$DEMO_DIR/openclaw.json"
cp "$SCRIPT_DIR/system_prompt.md" "$DEMO_DIR/system_prompt.md"

# Create a dummy README for the agent to read during the demo
cat > "$DEMO_DIR/README.md" <<'EOF'
# Demo Project

This is a sample project used to demonstrate Aperture's permission learning.
The agent will try to read this file, and Aperture will learn to allow it.
EOF

# ── 4. Initialize a fresh Aperture DB ───────────────────────────────
echo "Initializing Aperture database ..."
APERTURE_DB_PATH="$DEMO_DIR/aperture.db" aperture init-db

# ── 5. Print instructions ───────────────────────────────────────────
echo ""
echo "========================================"
echo "  Demo workspace ready!"
echo "========================================"
echo ""
echo "  cd $DEMO_DIR"
echo "  openclaw chat"
echo ""
echo "Try these prompts to see the learning loop:"
echo "  1. 'Read the file README.md'        -> Aperture denies (no history)"
echo "  2. Approve it 3 times               -> Aperture learns"
echo "  3. 'Read setup.py'                  -> Aperture auto-approves (learned pattern)"
echo "  4. 'Show me the permission patterns' -> See what Aperture learned"
echo ""
