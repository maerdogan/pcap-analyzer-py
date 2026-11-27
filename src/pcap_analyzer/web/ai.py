"""The AI tool the app uses for analysis in the background, and the language model it connects to.

The admin picks one tool from TOOLS and edits that tool's JSON configuration. For opencode the model is chosen from the models of the
providers that are connected on this host (what `opencode models` lists), and is written into the configuration's "model" key.
The settings are kept encrypted in the data folder, since the configuration may hold keys.
"""
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from .. import vault

TOOLS = {"opencode": "opencode"}
BIN_ENV = "PCAP_ANALYZER_OPENCODE"
CONFIG_ENV = "OPENCODE_CONFIG_CONTENT"  # opencode reads its configuration from here when it is set
DEFAULT_CONFIG = {"$schema": "https://opencode.ai/config.json"}
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
MODEL = re.compile(r"[\w.\-]+/\S+")
TIMEOUT_S = 20


def _path(settings):
    return settings.workdir / "ai.json"


def load(settings):
    saved = vault.read_json(_path(settings), {})
    tool = saved.get("tool") if saved.get("tool") in TOOLS else "opencode"
    config = saved.get("config") if isinstance(saved.get("config"), dict) else dict(DEFAULT_CONFIG)
    return dict(tool=tool, config=config)


def config_text(settings):
    return json.dumps(load(settings)["config"], indent=2)


def problem(tool, text):
    """The problem with new settings in plain words, or None."""
    if tool not in TOOLS:
        return "Choose one of the listed AI tools."
    try:
        value = json.loads(text or "{}")
    except ValueError:
        return "The configuration is not valid JSON."
    if not isinstance(value, dict):
        return "The configuration must be a JSON object, such as {\"model\": \"provider/model\"}."
    if "model" in value and not (isinstance(value["model"], str) and MODEL.fullmatch(value["model"])):
        return "The model must look like provider/model."
    return None


def save(settings, tool, text, model=""):
    """A chosen model replaces the configuration's model; an empty choice keeps what the JSON says."""
    config = json.loads(text or "{}")
    if model:
        config["model"] = model
    settings.workdir.mkdir(parents=True, exist_ok=True)
    vault.write_json(_path(settings), dict(tool=tool, config=config))


def binary():
    """The opencode program: from the environment, else PATH, else where `npm install --prefix ~/.local` puts it. None when missing."""
    for c in (os.environ.get(BIN_ENV), shutil.which("opencode"), str(Path.home() / ".local/bin/opencode")):
        if c and Path(c).is_file() and os.access(c, os.X_OK):
            return c
    return None


def version():
    exe = binary()
    if not exe:
        return None
    try:
        out = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=TIMEOUT_S).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    return ANSI.sub("", out).strip() or None


def environment(settings):
    """Environment for an opencode run: the saved configuration, so providers it defines are known."""
    return {**os.environ, CONFIG_ENV: json.dumps(load(settings)["config"])}


def models(settings):
    """provider/model names opencode can use now: those of the connected providers. Empty when opencode is missing or fails."""
    exe = binary()
    if not exe:
        return []
    try:
        out = subprocess.run([exe, "models"], capture_output=True, text=True, timeout=TIMEOUT_S, env=environment(settings), cwd=settings.workdir if settings.workdir.is_dir() else None).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    return [line for line in ANSI.sub("", out).splitlines() if MODEL.fullmatch(line.strip())]


def by_provider(names):
    """[(provider, [model names])] in the order the providers first appear."""
    out = {}
    for n in names:
        out.setdefault(n.split("/", 1)[0], []).append(n)
    return list(out.items())
