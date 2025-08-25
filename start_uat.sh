#!/usr/bin/env bash
set -euo pipefail

# Load .env so Poetry subprocess inherits all variables
if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
fi

# If you also keep a secrets file, prefer it *only if present*
if [[ -f "$HOME/.mysecrets/detoxai/api_key.dtx.uat.1" ]]; then
  export DETOXIO_API_KEY="$(cat "$HOME/.mysecrets/detoxai/api_key.dtx.uat.1")"
  # Keep OpenAI proxy in sync with Detoxio key if you want one key for both:
  export OPENAI_API_KEY="$DETOXIO_API_KEY"
fi

mkdir -p ./data

# Optional: print the host/base url once for sanity
echo "Detoxio host: ${DETOXIO_API_HOST:-unset}"
echo "OpenAI base url: ${OPENAI_BASE_URL:-unset}"

exec poetry run python gradio_app.py
