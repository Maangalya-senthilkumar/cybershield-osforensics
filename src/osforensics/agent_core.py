"""ReAct-pattern investigation agent backed by Ollama.

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

Setup
-----
    uv pip install ollama
"""
from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Dict, Generator, List, Optional, Tuple

import ollama
from dotenv import load_dotenv
load_dotenv(".env")
from . import agent_memory as memory
from . import agent_tools as tools

import requests

def _get_default_ollama_url():
    url = os.environ.get("OLLAMA_URL")
    if url:
        return url
    # Try localhost first
    try:
        # Using a direct socket check or requests with short timeout
        resp = requests.get("http://localhost:11434/api/tags", timeout=0.5)
        if resp.status_code == 200:
            return "http://localhost:11434/"
    except Exception:
        pass
    # Fallback to the specific remote IP
    return "http://100.73.207.125:11434/"

# ── Ollama configuration ───────────────────────────────────────────────────────

OLLAMA_URL     = _get_default_ollama_url()
DEFAULT_MODEL  = os.getenv("OLLAMA_MODEL", "qwen3.5")
MAX_OBS_CHARS  = 4000   # truncate large tool outputs before re-feeding to LLM

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
Respond ONLY with a valid JSON object. Do not include any prose outside the JSON.
All detailed reasoning and reports should be written in Markdown INSIDE the JSON fields.

When you need to call a tool:
{{
  "thought": "Your reasoning in Markdown",
  "action": "tool_name",
  "args": {{"param": "value"}}
}}

When you have enough evidence to answer (or for general/normal chat questions):
{{
  "thought": "Final summary of investigation steps or response reasoning",
  "action": "ANSWER",
  "answer": "DETAILED FORENSIC REPORT OR RESPONSE IN MARKDOWN FORMAT. Use headers, lists, and bold text for clarity."
}}

## CONSTRAINTS
- User's home directory is /home/dragon/ — all file paths are relative to this root
- Use forensic tools if the query requires evidence gathering; otherwise, answer directly
- Be specific — cite actual data values from tool results
- Check for chrome and brave browser artifacts, as well as common persistence locations
- DO NOT use wildcards (like '*') in file paths — tools expect specific paths or directory roots
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

def _build_client() -> ollama.Client:
    """Return an Ollama Client instance."""
    return ollama.Client(host=OLLAMA_URL)


def ollama_chat(
    messages: List[dict],
    model: str,
    client: ollama.Client,
    use_json: bool = True,
) -> str:
    """Send a conversation to Ollama and return the assistant text."""
    options = {"temperature": 0.1}
    
    if use_json:
        response = client.chat(
            model=model,
            messages=messages,
            format="json",
            options=options,
        )
    else:
        response = client.chat(
            model=model,
            messages=messages,
            options=options,
        )
    return response["message"]["content"]


# ── JSON parsing ───────────────────────────────────────────────────────────────

def sanitize_escapes(text: str) -> str:
    r"""Remove backslashes before characters that are not valid JSON escape targets."""
    return re.sub(r'\\([^"\\/bfnrtu\n\r]|u(?![0-9a-fA-F]{4}))', r'\1', text)


def parse_json(text: str) -> dict:
    """Extract and parse the JSON object from an LLM response.
    
    If no valid JSON is found, returns a default 'ANSWER' structure 
    using the raw text as the answer.
    """
    text_stripped = text.strip()
    
    # Try to find content inside markdown code blocks first
    m_code = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text_stripped, re.DOTALL)
    target = m_code.group(1) if m_code else None
    
    if not target:
        # Fallback: search for the outermost braces
        m_braces = re.search(r"(\{.*\})", text_stripped, re.DOTALL)
        target = m_braces.group(1) if m_braces else None

    if target:
        target = sanitize_escapes(target)
        try:
            return json.loads(target)
        except json.JSONDecodeError:
            # One last try: remove anything before the first { and after the last }
            try:
                start = target.find('{')
                end = target.rfind('}') + 1
                if start != -1 and end > 0:
                    return json.loads(target[start:end])
            except Exception:
                pass

    # If we reached here, no valid JSON was found. 
    # Treat the entire response as a direct answer (Normal Chat).
    return {
        "thought": "Direct response generated.",
        "action": "ANSWER",
        "answer": text_stripped
    }


def _truncate(data: Any, max_chars: int = MAX_OBS_CHARS) -> str:
    s = json.dumps(data, default=str)
    if len(s) > max_chars:
        return s[:max_chars] + f"… [truncated {len(s) - max_chars} chars]"
    return s


# ── Agent ──────────────────────────────────────────────────────────────────────

class InvestigationAgent:
    def __init__(self, model: str = DEFAULT_MODEL, max_steps: int = 6):
        self.model     = model
        self.max_steps = max_steps
        self._client: Optional[ollama.Client] = None

    def _get_client(self) -> ollama.Client:
        """Lazily initialise and cache the Ollama client."""
        if self._client is None:
            self._client = _build_client()
        return self._client

    # ── Ollama health / model listing ─────────────────────────────────────────

    def _extract_model_names(self, response: Any) -> List[str]:
        """Helper to extract model names from both old dict and new object responses."""
        if hasattr(response, 'models'):
            return [m.model for m in response.models]
        if isinstance(response, dict):
            return [m.get("name", m.get("model")) for m in response.get("models", [])]
        return []

    def check_ollama(self) -> Tuple[bool, str]:
        """Check Ollama connectivity and return current model."""
        try:
            client = self._get_client()
            res = client.list()
            available = self._extract_model_names(res)
            if not available:
                return False, "No models available in Ollama"
            # Return model name if found or just true/the model we want
            return True, self.model
        except Exception as e:
            return False, f"Ollama connectivity error: {e}"

    def list_models(self) -> List[str]:
        """Return the list of Ollama models."""
        try:
            client = self._get_client()
            res = client.list()
            return self._extract_model_names(res)
        except Exception:
            return []

    # ── Simple Chat ───────────────────────────────────────────────────────────

    def chat(self, prompt: str, use_json: bool = False) -> str:
        """One-off interaction with the AI model."""
        client = self._get_client()
        messages = [
            {"role": "system", "content": "You are a professional digital forensics investigator."},
            {"role": "user", "content": prompt}
        ]
        return ollama_chat(messages, self.model, client, use_json=use_json)

    # ── ReAct loop ─────────────────────────────────────────────────────────────

    def run(
        self,
        query: str,
        session_id: Optional[str] = None,
    ) -> Generator[Dict, None, None]:
        if session_id is None:
            session_id = memory.create_session(query)
        yield {"type": "session", "session_id": session_id}

        client = self._get_client()
        system = _system_prompt(self.max_steps)

        messages: List[dict] = [
            {"role": "system", "content": system},
            {"role": "user",   "content": query},
        ]

        for step in range(1, self.max_steps + 1):
            try:
                raw    = ollama_chat(messages, self.model, client, use_json=True)
                parsed = parse_json(raw)
            except Exception as exc:
                yield {"type": "error", "message": f"Step {step} LLM error: {exc}"}
                return

            thought = parsed.get("thought", "")
            action  = parsed.get("action",  "").strip()
            args    = parsed.get("args",    {})

            # ── Final answer ───────────────────────────────────────────────────
            if action == "ANSWER":
                answer = parsed.get("answer") or thought
                if not isinstance(answer, str):
                    answer = json.dumps(answer, indent=2)
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

        # ── Max steps reached ──────────────────────────────────────────────────
        messages.append({
            "role": "user",
            "content": (
                "You have reached the maximum investigation steps. "
                "Provide your final forensic analysis based on all evidence gathered. "
                'Respond with JSON: {"thought": "...", "action": "ANSWER", "answer": "..."}'
            ),
        })
        try:
            raw    = ollama_chat(messages, self.model, client, use_json=True)
            parsed = parse_json(raw)
            answer = parsed.get("answer") or parsed.get("thought", "Investigation complete.")
            if not isinstance(answer, str):
                answer = json.dumps(answer, indent=2)
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