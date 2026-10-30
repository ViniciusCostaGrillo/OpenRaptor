"""OpenCode subprocess transport for RAPTOR.

Builds `opencode run --format json` commands and parses their JSON-stream output.
The headless subprocess counterpart for OpenCode orchestration.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
from typing import Any

logger = logging.getLogger(__name__)


def parse_opencode_json_stream(stream_output: str) -> str:
    """Parse newline-delimited JSON stream from opencode run --format json.
    
    Extracts text chunks from JSON event lines (e.g. step_start, text, step_finish).
    Falls back gracefully if the output is raw text.
    """
    if not stream_output:
        return ""
    
    extracted_text: list[str] = []
    lines = stream_output.splitlines()
    has_json = False

    for line in lines:
        line_str = line.strip()
        if not line_str:
            continue
        try:
            event = json.loads(line_str)
            has_json = True
            if isinstance(event, dict):
                # Check known event shapes
                if event.get("type") == "text" and "content" in event:
                    extracted_text.append(str(event["content"]))
                elif "content" in event and isinstance(event["content"], str):
                    extracted_text.append(event["content"])
                elif "text" in event and isinstance(event["text"], str):
                    extracted_text.append(event["text"])
        except (json.JSONDecodeError, ValueError):
            continue

    if has_json and extracted_text:
        return "".join(extracted_text)
    
    # Fallback to returning raw output stripped of leading/trailing whitespace
    return stream_output.strip()


def run_opencode_turn(
    prompt: str,
    model: str | None = None,
    system: str | None = None,
    timeout: int = 180,
    cwd: str | None = None,
) -> str:
    """Execute a prompt via `opencode run --format json` in headless mode."""
    cmd = ["opencode", "run", "--standalone", "--auto", "--format", "json"]
    
    if model:
        cmd.extend(["--model", str(model)])
    
    full_prompt = prompt
    if system:
        full_prompt = f"System instruction: {system}\n\nUser request: {prompt}"
        
    cmd.append(full_prompt)

    env = os.environ.copy()
    env["_RAPTOR_TRUSTED"] = "1"

    logger.debug("Executing OpenCode headless turn: %s", cmd[:5])

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            env=env,
        )
        stdout_bytes, stderr_bytes = proc.communicate(timeout=timeout)
    except (subprocess.TimeoutExpired, OSError) as e:
        logger.error("OpenCode subprocess execution failed: %s", e)
        raise RuntimeError(f"OpenCode execution error: {e}") from e

    stdout_text = stdout_bytes.decode("utf-8", errors="replace")
    if proc.returncode != 0:
        stderr_text = stderr_bytes.decode("utf-8", errors="replace")
        logger.warning(
            "OpenCode exited with non-zero code %d: %s", proc.returncode, stderr_text[:500]
        )
        # Even with non-zero exit, check if partial text was produced
        parsed = parse_opencode_json_stream(stdout_text)
        if parsed:
            return parsed
        raise RuntimeError(
            f"OpenCode failed with code {proc.returncode}: {stderr_text.strip() or stdout_text.strip()}"
        )

    return parse_opencode_json_stream(stdout_text)
