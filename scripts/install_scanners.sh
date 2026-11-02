#!/usr/bin/env bash
# Installs the two optional external scanners into their own virtualenvs under ~/.venvs
# (AgentGuard finds them there automatically - no environment variables needed):
#   ~/.venvs/cisco        Cisco AI Defense skill-scanner        (PyPI: cisco-ai-skill-scanner)
#   ~/.venvs/skillspector NVIDIA SkillSpector                   (GitHub: NVIDIA/SkillSpector, needs Python 3.12-3.15)
#
# Python choice matters: SkillSpector depends on yara-python, which ships binary wheels for 3.12/3.13 but
# NOT for 3.14 (pip would compile it from source and often fails). So we prefer 3.13, then 3.12, and use
# `uv` to download one when the system has neither. Override with AGENTGUARD_SCANNER_PYTHON=/path/to/python.
#
# Usage: bash scripts/install_scanners.sh [cisco|nvidia|all]      (default: all)
set -euo pipefail

WHICH="${1:-all}"
VENV_DIR="${AGENTGUARD_VENV_DIR:-$HOME/.venvs}"
NVIDIA_SPEC="${AGENTGUARD_NVIDIA_SPEC:-git+https://github.com/NVIDIA/SkillSpector.git}"
CISCO_SPEC="${AGENTGUARD_CISCO_SPEC:-cisco-ai-skill-scanner}"
mkdir -p "$VENV_DIR"

py_version() { "$1" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || true; }

pick_python() {   # prints a python executable suitable for SkillSpector (3.12-3.15), preferring wheels
  if [ -n "${AGENTGUARD_SCANNER_PYTHON:-}" ]; then echo "$AGENTGUARD_SCANNER_PYTHON"; return; fi
  for candidate in python3.13 python3.12; do
    if command -v "$candidate" >/dev/null 2>&1; then command -v "$candidate"; return; fi
  done
  return 1
}

make_venv() {     # make_venv <dir> <python-or-empty> <uv-python-version>
  local dir="$1" py="$2" want="$3"
  rm -rf "$dir"
  if [ -n "$py" ]; then
    "$py" -m venv "$dir"
  elif command -v uv >/dev/null 2>&1; then
    echo "  no Python $want found - letting uv download one"
    uv venv --python "$want" "$dir"
    uv pip install --python "$dir/bin/python" pip >/dev/null
  else
    return 1
  fi
}

install_cisco() {
  echo "==> Cisco skill-scanner -> $VENV_DIR/cisco"
  local py="${AGENTGUARD_SCANNER_PYTHON:-$(pick_python || true)}"
  [ -n "$py" ] || py="$(command -v python3)"
  make_venv "$VENV_DIR/cisco" "$py" 3.13
  "$VENV_DIR/cisco/bin/pip" install --quiet --upgrade pip
  "$VENV_DIR/cisco/bin/pip" install --quiet "$CISCO_SPEC"
  "$VENV_DIR/cisco/bin/skill-scanner" --help >/dev/null && echo "    OK: $("$VENV_DIR/cisco/bin/python" --version)"
}

install_nvidia() {
  echo "==> NVIDIA SkillSpector -> $VENV_DIR/skillspector"
  local py; py="$(pick_python || true)"
  if ! make_venv "$VENV_DIR/skillspector" "$py" 3.13; then
    py="$(command -v python3 || true)"
    local v; v="$(py_version "$py")"
    case "$v" in
      3.12|3.13|3.14|3.15)
        echo "  WARNING: no Python 3.12/3.13 and no uv; using Python $v."
        echo "           If the install fails building yara-python run:  sudo apt install -y build-essential python3-dev libssl-dev"
        echo "           or install uv (pip install uv) and re-run this script."
        make_venv "$VENV_DIR/skillspector" "$py" "$v" ;;
      *) echo "  ERROR: SkillSpector needs Python 3.12-3.15 (found '${v:-none}'). Install uv (pip install uv) and re-run."; return 1 ;;
    esac
  fi
  "$VENV_DIR/skillspector/bin/pip" install --quiet --upgrade pip
  "$VENV_DIR/skillspector/bin/pip" install --quiet "$NVIDIA_SPEC"
  "$VENV_DIR/skillspector/bin/skillspector" --version && echo "    OK: $("$VENV_DIR/skillspector/bin/python" --version)"
}

case "$WHICH" in
  cisco)  install_cisco ;;
  nvidia) install_nvidia ;;
  all)    install_cisco; install_nvidia ;;
  *) echo "usage: $0 [cisco|nvidia|all]"; exit 2 ;;
esac

echo
echo "Done. Check what AgentGuard sees with:   python -m agentguard.cli scanners"
