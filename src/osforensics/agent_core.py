"""ReAct-pattern investigation agent backed by a local Ollama LLM.

Architecture
------------
    User query
        ↓
    InvestigationAgent.run()   ← ReAct loop
        ↓
    LLM (Ollama) → {thought, action, args}
        ↓
    agent_tools.execute_tool()
        ↓
    agent_memory  (episode + evidence store)
        ↓
    LLM receives observation → next step  (repeat)
        ↓
    LLM → {action: "ANSWER", answer: "..."}

The run() method is a generator that yields event dicts so the API layer
can stream them to the frontend via SSE as they happen.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, Generator, List, Optional, Tuple

import requests

from . import agent_memory as memory
from . import agent_tools as tools

_DEFAULT_OLLAMA_URL = "http://lab:11434"
OLLAMA_URL   = os.environ.get("OLLAMA_HOST", _DEFAULT_OLLAMA_URL).rstrip("/")
DEFAULT_MODEL = "qwen2.5:7b"
MAX_OBS_CHARS = 4000   # truncate large tool outputs before re-feeding to LLM

# ── System prompt ──────────────────────────────────────────────────────────────

_SYSTEM = """\
You are an expert digital forensics investigator embedded in an OS forensics workstation.
You systematically gather and analyse digital evidence to identify security incidents,
malware persistence, unauthorised access, and suspicious activity.

## AVAILABLE TOOLS
{tool_list}

## INVESTIGATION PROTOCOL
Work like a real forensic investigator:
1. Understand the investigation goal
2. Choose the most relevant tool to collect evidence
3. Analyse the results critically — look for anomalies, IOCs, and patterns
4. Build a chain of evidence before drawing conclusions
5. Cite specific values (file paths, PIDs, IPs, timestamps) in your answer

## RESPONSE FORMAT
Respond ONLY with a valid JSON object — no markdown, no prose outside the JSON.

When you need to call a tool:
{{
  "thought": "Your reasoning: what evidence you need and why this tool",
  "action": "tool_name",
  "args": {{"param": "value"}}
}}

When you have enough evidence to answer:
{{
  "thought": "Summary of everything gathered",
  "action": "ANSWER",
  "answer": "Detailed forensic findings with specific evidence citations and IOCs"
}}

## CONSTRAINTS
- Always use at least one tool before answering
- Be specific — cite actual data values from tool results
- If a tool returns an error, try an alternative approach or explain the limitation
- Maximum {max_steps} investigation steps, then provide your best analysis
"""


def _build_tool_list() -> str:
    lines = []
    for name, t in tools.TOOL_REGISTRY.items():
        params = ", ".join(f"{k}: {v}" for k, v in t["params"].items())
        lines.append(f"  {name}({params})\n    → {t['description']}")
    return "\n".join(lines)


def _system_prompt(max_steps: int) -> str:
    return _SYSTEM.format(tool_list=_build_tool_list(), max_steps=max_steps)


# ── Ollama helpers ─────────────────────────────────────────────────────────────

def _ollama_chat(messages: List[dict], model: str, temperature: float = 0.1) -> str:
    """Call the Ollama /api/chat endpoint and return the assistant content."""
    resp = requests.post(
        f"{OLLAMA_URL}/api/chat",
        json={
            "model":   model,
            "messages": messages,
            "stream":  False,
            "options": {"temperature": temperature, "num_predict": 2048},
        },
        timeout=180,
    )
    resp.raise_for_status()
    return resp.json()["message"]["content"]


def _sanitize_escapes(text: str) -> str:
    r"""Remove backslashes before characters that are not valid JSON escape targets.

    LLMs commonly emit  \'  inside JSON strings, which is illegal in JSON.
    Valid JSON escape sequences are: \" \\ \/ \b \f \n \r \t \uXXXX.
    Anything else (e.g. \' \! \,) has its backslash dropped.
    """
    return re.sub(r'\\([^"\\/bfnrtu\n\r]|u(?![0-9a-fA-F]{4}))', r'\1', text)


def _parse_json(text: str) -> dict:
    """Extract and parse the JSON object from an LLM response.

    Tolerates: markdown code fences, invalid escape sequences (e.g. \'),
    truncated responses (token-limit cut-off), and extra whitespace.
    """
    text = text.strip()
    # Strip ```json ... ``` fences if present
    if text.startswith("```"):
        text = re.sub(r"^```[a-z]*\n?", "", text)
        text = re.sub(r"\n?```\s*$", "", text.strip())

    # Sanitize invalid escape sequences before any JSON parse attempt
    text = _sanitize_escapes(text)

    # Try to find and parse a complete { ... } block
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group())
        except json.JSONDecodeError:
            pass

    # Response was truncated — find the opening brace, heal, then parse
    start = text.find("{")
    if start != -1:
        fragment = text[start:]
        healed = _heal_json(fragment)
        try:
            return json.loads(healed)
        except json.JSONDecodeError:
            pass

    raise ValueError(f"No valid JSON in LLM response: {text[:300]!r}")


def _heal_json(fragment: str) -> str:
    """Best-effort: close unclosed strings and braces in a truncated JSON object.

    Handles three truncation scenarios:
      A) value string cut off mid-way  → close the string, then close braces
      B) key string cut off            → drop the dangling key, close braces
      C) value missing after colon     → drop the dangling key+colon, close braces
    """
    in_string           = False
    escape              = False
    depth               = 0
    last_colon_pos      = -1  # index of last bare ':' at top-level
    last_complete_pos   =  0  # index just after last fully closed key-value pair
    open_string_is_val  = False  # True when current open string is a value
    last_non_ws         = ""    # last non-ws char seen outside strings

    for i, ch in enumerate(fragment):
        if escape:
            escape = False
            continue
        if ch == "\\" and in_string:
            escape = True
            continue
        if ch == '"':
            if not in_string:
                open_string_is_val = (last_non_ws == ":")
            in_string = not in_string
            continue
        if not in_string:
            if ch == "{":
                depth += 1
                last_non_ws = ch
            elif ch == "}":
                depth -= 1
                if depth > 0:
                    last_complete_pos = i + 1
                last_non_ws = ch
            elif ch == ",":
                if depth == 1:
                    last_complete_pos = i + 1
                last_non_ws = ch
            elif ch == ":":
                if depth == 1:
                    last_colon_pos = i
                last_non_ws = ch
            elif not ch.isspace():
                last_non_ws = ch

    if depth <= 0:
        return fragment   # already valid/closed

    result   = fragment + ('"' if in_string else "")
    stripped = result.rstrip()
    last_char = stripped[-1] if stripped else ""

    def _close(base: str) -> str:
        base = base.rstrip().rstrip(",")
        return (base if base else "{") + "}" * depth

    # Scenario C: ends with bare ':' — value completely absent
    if last_char == ":":
        return _close(stripped[:last_complete_pos])

    # Scenario B: the unclosed/just-closed string was a KEY
    if in_string and not open_string_is_val:
        return _close(stripped[:last_complete_pos])

    # Scenario A: value string truncated — close it and shut the braces
    return _close(stripped)


def _truncate(data: Any, max_chars: int = MAX_OBS_CHARS) -> str:
    s = json.dumps(data, default=str)
    if len(s) > max_chars:
        return s[:max_chars] + f"… [truncated {len(s) - max_chars} chars]"
    return s


# ── Agent ──────────────────────────────────────────────────────────────────────

class InvestigationAgent:
    def __init__(self, model: str = DEFAULT_MODEL, max_steps: int = 6):
        self.model = model
        self.max_steps = max_steps

    # ── Ollama health check ────────────────────────────────────────────────────

    def check_ollama(self) -> Tuple[bool, str]:
        """Return (available: bool, model_name_or_error_message: str)."""
        try:
            r = requests.get(f"{OLLAMA_URL}/api/tags", timeout=5)
            r.raise_for_status()
            models = [m["name"] for m in r.json().get("models", [])]
            if not models:
                return False, "No models installed — run: ollama pull qwen2.5:7b"
            preferred = [m for m in models if self.model.split(":")[0] in m]
            self.model = preferred[0] if preferred else models[0]
            return True, self.model
        except requests.ConnectionError as e:
            cause = str(e.__cause__ or e).split("\n")[0]
            return False, f"Cannot reach Ollama at {OLLAMA_URL}: {cause}"
        except Exception as e:
            return False, f"Ollama error ({type(e).__name__}): {e}"

    def list_models(self) -> List[str]:
        """Return the list of locally installed Ollama model names."""
        try:
            r = requests.get(f"{OLLAMA_URL}/api/tags", timeout=5)
            r.raise_for_status()
            return [m["name"] for m in r.json().get("models", [])]
        except Exception:
            return []

    # ── ReAct loop ─────────────────────────────────────────────────────────────

    def run(
        self,
        query: str,
        session_id: Optional[str] = None,
    ) -> Generator[Dict, None, None]:
        """Execute the ReAct investigation loop.

        Yields event dicts (suitable for SSE serialisation):
          {"type": "session",  "session_id": str}
          {"type": "step",     "step": int, "thought": str, "action": str,
                               "args": dict, "observation": dict}
          {"type": "answer",   "text": str, "session_id": str, "steps": int}
          {"type": "error",    "message": str}
        """
        if session_id is None:
            session_id = memory.create_session(query)
        yield {"type": "session", "session_id": session_id}

        messages: List[dict] = [
            {"role": "system",  "content": _system_prompt(self.max_steps)},
            {"role": "user",    "content": query},
        ]

        for step in range(1, self.max_steps + 1):

            # ── LLM call ──────────────────────────────────────────────────────
            try:
                raw    = _ollama_chat(messages, self.model)
                parsed = _parse_json(raw)
            except requests.ConnectionError as e:
                cause = str(e.__cause__ or e).split("\n")[0]
                yield {"type": "error", "message": f"Lost connection to Ollama at {OLLAMA_URL}: {cause}"}
                return
            except Exception as e:
                yield {"type": "error", "message": f"Step {step} LLM error: {e}"}
                return

            thought = parsed.get("thought", "")
            action  = parsed.get("action",  "").strip()
            args    = parsed.get("args",    {})

            # ── Final answer ───────────────────────────────────────────────────
            if action == "ANSWER":
                answer = parsed.get("answer") or thought
                memory.add_episode(session_id, step, thought, "ANSWER", {}, {"answer": answer})
                yield {
                    "type": "answer",
                    "text": answer,
                    "session_id": session_id,
                    "steps": step,
                }
                return

            if not action:
                yield {"type": "error", "message": f"Step {step}: LLM returned no action."}
                return

            # ── Tool execution ─────────────────────────────────────────────────
            observation = tools.execute_tool(action, args)
            memory.add_episode(session_id, step, thought, action, args, observation)
            memory.store_evidence(session_id, action, observation, source=str(args))

            yield {
                "type":        "step",
                "step":        step,
                "thought":     thought,
                "action":      action,
                "args":        args,
                "observation": observation,
            }

            # Feed truncated observation back for the next LLM call
            obs_str = _truncate(observation)
            messages.append({"role": "assistant", "content": raw})
            messages.append({
                "role": "user",
                "content": (
                    f"Tool '{action}' result:\n{obs_str}\n\n"
                    "Continue the investigation. If you have gathered enough "
                    "evidence, provide your ANSWER now. Otherwise call the next "
                    "appropriate tool."
                ),
            })

        # ── Max steps reached: force final answer ──────────────────────────────
        messages.append({
            "role": "user",
            "content": (
                "You have reached the maximum investigation steps. "
                "Provide your final forensic analysis based on all evidence gathered. "
                'Respond with JSON: {"thought": "...", "action": "ANSWER", "answer": "..."}'
            ),
        })
        try:
            raw    = _ollama_chat(messages, self.model)
            parsed = _parse_json(raw)
            answer = parsed.get("answer") or parsed.get("thought", "Investigation complete.")
            yield {
                "type": "answer",
                "text": answer,
                "session_id": session_id,
                "steps": self.max_steps,
            }
        except Exception as e:
            yield {"type": "error", "message": f"Failed to generate final answer: {e}"}


# ── Module-level singleton ─────────────────────────────────────────────────────

_agent: Optional[InvestigationAgent] = None


def get_agent() -> InvestigationAgent:
    global _agent
    if _agent is None:
        _agent = InvestigationAgent()
    return _agent
