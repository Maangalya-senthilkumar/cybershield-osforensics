"""Multi-Agent Orchestration Framework for OS Forensics (Ollama version).

Architecture
------------
    User Query
        ↓
    OrchestratorAgent.run()          ← Top-level ReAct loop
        ↓
    LLM decides which sub-agent to dispatch to
        ↓
    dispatch_to_subagent("browser_agent", task=..., path=...)
        ↓
    SubAgent.run()                   ← Domain-specialist ReAct loop
        ↓
    Domain tools (browser, memory, persistence, …)
        ↓
    SubAgent yields structured findings → Orchestrator
        ↓
    Orchestrator aggregates + synthesises a final forensic answer
"""
from __future__ import annotations

import json
import os
import re
import time
import traceback
from typing import Any, Dict, Generator, List, Optional, Tuple

import ollama

from . import agent_memory as mem

import requests

def _get_default_ollama_url():
    url = os.environ.get("OLLAMA_URL")
    if url:
        return url
    try:
        resp = requests.get("http://localhost:11434/api/tags", timeout=0.5)
        if resp.status_code == 200:
            return "http://localhost:11434/"
    except Exception:
        pass
    return "http://100.73.207.125:11434/"

# ── Ollama config ──────────────────────────────────────────────────────────────

OLLAMA_URL      = _get_default_ollama_url()
DEFAULT_MODEL   = os.environ.get("OLLAMA_MODEL", "qwen3.5")
MAX_OBS_CHARS   = 4_000

# ── Domain tool registries ─────────────────────────────────────────────────────

def _get_sub_registries() -> Dict[str, Dict]:
    """Return per-domain tool registries, imported lazily."""
    from .sub_tools import (
        BROWSER_TOOLS, MEMORY_TOOLS, PERSISTENCE_TOOLS,
        FILESYSTEM_TOOLS, SERVICES_TOOLS, CONFIG_TOOLS,
        MULTIMEDIA_TOOLS, TAILS_TOOLS,
    )
    return {
        "browser_agent":     BROWSER_TOOLS,
        "memory_agent":      MEMORY_TOOLS,
        "persistence_agent": PERSISTENCE_TOOLS,
        "filesystem_agent":  FILESYSTEM_TOOLS,
        "services_agent":    SERVICES_TOOLS,
        "config_agent":      CONFIG_TOOLS,
        "multimedia_agent":  MULTIMEDIA_TOOLS,
        "tails_agent":       TAILS_TOOLS,
    }

# ── Sub-agent descriptions ─────────────────────────────────────────────────────

_SUBAGENT_DESCRIPTIONS = {
    "browser_agent": (
        "Forensic analysis of web browsers. "
        "Extracts history, downloads, cookies, saved passwords, extensions "
        "from Chrome, Firefox, Brave, Tor Browser, and others."
    ),
    "memory_agent": (
        "Memory dump analysis via Volatility3. "
        "Recovers running/hidden processes, network connections, bash history, "
        "loaded kernel modules, and malware-injected regions (malfind)."
    ),
    "persistence_agent": (
        "Persistence mechanism detection. "
        "Checks crontabs, systemd service units, shell startup files "
        "(.bashrc/.profile/rc.local), and SSH authorized_keys for backdoors."
    ),
    "filesystem_agent": (
        "Filesystem-level forensics. "
        "Detects OS identity, offensive/privacy tools installed, deleted files, "
        "and builds a chronological activity timeline from filesystem timestamps."
    ),
    "services_agent": (
        "System service enumeration and anomaly detection. "
        "Lists all systemd/init services, flags unknown or suspicious ones "
        "that may represent malware persistence or tunnels."
    ),
    "config_agent": (
        "Security configuration audit. "
        "Reviews SSH daemon config, sudo rules, firewall (ufw/iptables), "
        "PAM config, sysctl kernel parameters for weaknesses."
    ),
    "multimedia_agent": (
        "Multimedia file forensics. "
        "Scans images/video/audio for EXIF metadata, embedded GPS coordinates, "
        "steganography indicators, and hidden data."
    ),
    "tails_agent": (
        "Tails OS and Tor specialised forensics. "
        "Detects amnesic boot parameters, Tor activity, onion destinations, "
        "hidden services, persistence volumes, and anti-forensic behaviour."
    ),
}

# ── Shared LLM helpers ─────────────────────────────────────────────────────────

def _build_client() -> ollama.Client:
    return ollama.Client(host=OLLAMA_URL)


def _ollama_call(messages: List[dict], model: str, client: ollama.Client, use_json: bool = True) -> str:
    """Send history to Ollama. Returns raw text."""
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


def _sanitize_escapes(text: str) -> str:
    return re.sub(r'\\([^"\\/bfnrtu\n\r]|u(?![0-9a-fA-F]{4}))', r'\1', text)


def _parse_json(text: str) -> dict:
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
        target = _sanitize_escapes(target)
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

    # No valid JSON found. Treat as direct answer.
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


# ── Sub-agent ──────────────────────────────────────────────────────────────────

_SUB_SYSTEM = """\
You are a specialist forensic sub-agent: {role_name}.

## YOUR DOMAIN
{domain_description}

## AVAILABLE TOOLS
{tool_list}

## PROTOCOL
1. Reason about what evidence to collect in this domain.
2. Call tools one at a time.
3. Once you have sufficient evidence, emit ANSWER.

## RESPONSE FORMAT
Respond ONLY with a valid JSON object. Do not include any prose outside the JSON.
All detailed reasoning and reports should be written in Markdown INSIDE the JSON fields.

Tool call:
{{
  "thought": "Brief summary of reasoning in Markdown",
  "action":  "tool_name",
  "args":    {{"param": "value"}}
}}

When you have enough evidence to answer (or for general questions):
{{
  "thought": "Brief summary of findings or response reasoning",
  "action":  "ANSWER",
  "answer":  "DETAILED FORENSIC REPORT OR RESPONSE IN MARKDOWN FORMAT. Use headers, lists, and bold text for clarity."
}}

## CONSTRAINTS
- Use forensic tools if the task requires evidence gathering; otherwise, answer directly.
- Cite specific file paths, PIDs, timestamps, IPs in your answer.
- Maximum {max_steps} steps, then give best-effort answer.
- Task context: {task}
"""


class SubAgent:
    """A domain-specialist ReAct agent with a restricted tool set."""

    def __init__(
        self,
        agent_id: str,
        description: str,
        tool_registry: Dict[str, dict],
        client: ollama.Client,
        model: str,
        max_steps: int = 5,
    ):
        self.agent_id    = agent_id
        self.description = description
        self.tools       = tool_registry
        self.client      = client
        self.model       = model
        self.max_steps   = max_steps

    def _tool_list_str(self) -> str:
        lines = []
        for name, t in self.tools.items():
            params = ", ".join(f"{k}: {v}" for k, v in t["params"].items())
            lines.append(f"  {name}({params})\n    → {t['description']}")
        return "\n".join(lines) or "  (no tools available)"

    def _system(self, task: str) -> str:
        return _SUB_SYSTEM.format(
            role_name=self.agent_id,
            domain_description=self.description,
            tool_list=self._tool_list_str(),
            task=task,
            max_steps=self.max_steps,
        )

    def _execute(self, action: str, args: dict) -> dict:
        if action not in self.tools:
            return {"error": f"Tool '{action}' not in {self.agent_id}'s registry."}
        try:
            return self.tools[action]["fn"](**args)
        except Exception as e:
            return {"error": str(e), "trace": traceback.format_exc()}

    def run(
        self,
        task: str,
        session_id: str,
        parent_step: int,
    ) -> Generator[Dict, None, None]:
        system   = self._system(task)
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": task}
        ]
        steps_taken = 0

        for step in range(1, self.max_steps + 1):
            try:
                raw    = _ollama_call(messages, self.model, self.client, use_json=True)
                parsed = _parse_json(raw)
            except Exception as exc:
                yield {
                    "type":     "subagent_error",
                    "agent_id": self.agent_id,
                    "message":  f"[{self.agent_id}] LLM error at step {step}: {exc}",
                }
                return

            thought = parsed.get("thought", "")
            action  = parsed.get("action",  "").strip()
            args    = parsed.get("args",    {})

            if action == "ANSWER":
                answer = parsed.get("answer") or thought
                if not isinstance(answer, str):
                    answer = json.dumps(answer, indent=2)
                mem.add_episode(session_id, parent_step * 100 + step,
                                thought, "ANSWER", {}, {"answer": answer, "agent": self.agent_id})
                yield {
                    "type":       "subagent_result",
                    "agent_id":   self.agent_id,
                    "steps_taken": steps_taken,
                    "answer":     answer,
                }
                return

            observation = self._execute(action, args)
            steps_taken += 1

            mem.add_episode(session_id, parent_step * 100 + step,
                            thought, action, args, observation)
            mem.store_evidence(session_id, f"{self.agent_id}.{action}",
                               observation, source=str(args))

            yield {
                "type":        "subagent_step",
                "agent_id":    self.agent_id,
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
                    "Continue analysing. Provide ANSWER when you have enough evidence."
                ),
            })

        messages.append({
            "role": "user",
            "content": "Maximum steps reached. Provide your best forensic findings now."
        })
        try:
            raw    = _ollama_call(messages, self.model, self.client)
            parsed = _parse_json(raw)
            answer = parsed.get("answer") or parsed.get("thought", "No findings.")
            if not isinstance(answer, str):
                answer = json.dumps(answer, indent=2)
        except Exception as e:
            answer = f"[{self.agent_id}] Could not generate final answer: {e}"

        yield {
            "type":        "subagent_result",
            "agent_id":    self.agent_id,
            "steps_taken": steps_taken,
            "answer":      answer,
        }


# ── Orchestrator ───────────────────────────────────────────────────────────────

_ORCH_SYSTEM = """\
You are the chief forensic orchestrator. You coordinate a team of specialist
sub-agents to investigate a digital evidence source comprehensively.

## AVAILABLE SUB-AGENTS
{subagent_list}

## SPECIAL ACTION
dispatch_subagent(agent_id, task, path)
  → Dispatch a sub-agent to perform domain-specific investigation.
    agent_id : one of the agent names above
    task     : natural-language description of what you need from that agent
    path     : absolute filesystem path or dump file to investigate

## RESPONSE FORMAT
Respond ONLY with a valid JSON object. Do not include any prose outside the JSON.
All detailed reasoning and reports should be written in Markdown INSIDE the JSON fields.

Dispatch a sub-agent:
{{
  "thought": "Brief summary of reasoning in Markdown",
  "action":  "dispatch_subagent",
  "args":    {{"agent_id": "browser_agent", "task": "...", "path": "..."}}
}}

Final synthesis (or direct response for general questions):
{{
  "thought": "Brief summary of findings or response reasoning",
  "action":  "ANSWER",
  "answer":  "DETAILED FORENSIC REPORT OR RESPONSE IN MARKDOWN FORMAT. Use headers, lists, and bold text for clarity."
}}

## ORCHESTRATION RULES
- Decompose the user query into domain-specific sub-tasks if it requires forensic analysis.
- For general or normal chat questions, answer directly using the ANSWER action.
- Dispatch agents whose domains are relevant to the query.
- Synthesise ALL sub-agent answers into a cohesive forensic narrative.
- Maximum {max_steps} orchestration steps total.
- Initial investigation path: {initial_path}
"""


class OrchestratorAgent:
    """Top-level agent that decomposes a query and delegates to sub-agents."""

    def __init__(self, model_name: str = DEFAULT_MODEL, max_steps: int = 10):
        self.model_name = model_name
        self.max_steps  = max_steps
        self._client: Optional[ollama.Client] = None
        self._sub_registries: Optional[Dict[str, Dict]] = None

    def _get_client(self) -> ollama.Client:
        if self._client is None:
            self._client = _build_client()
        return self._client

    def _get_sub_registries(self) -> Dict[str, Dict]:
        if self._sub_registries is None:
            self._sub_registries = _get_sub_registries()
        return self._sub_registries

    def _build_system(self, initial_path: str) -> str:
        lines = []
        for agent_id, desc in _SUBAGENT_DESCRIPTIONS.items():
            lines.append(f"  {agent_id}\n    {desc}")
        return _ORCH_SYSTEM.format(
            subagent_list="\n".join(lines),
            max_steps=self.max_steps,
            initial_path=initial_path,
        )

    def _dispatch(
        self,
        agent_id: str,
        task: str,
        path: str,
        session_id: str,
        orch_step: int,
    ) -> Generator[Dict, None, None]:
        registries = self._get_sub_registries()
        if agent_id not in registries:
            yield {"type": "subagent_error", "agent_id": agent_id, "message": f"Unknown sub-agent '{agent_id}'."}
            return

        description = _SUBAGENT_DESCRIPTIONS.get(agent_id, "Specialist forensic agent")
        sub = SubAgent(
            agent_id = agent_id,
            description = description,
            tool_registry = registries[agent_id],
            client = self._get_client(),
            model = self.model_name,
            max_steps = 5,
        )
        full_task = f"{task}\n\nFilesystem/dump path: {path}"
        yield {"type": "subagent_start", "agent_id": agent_id, "task": full_task}
        yield from sub.run(full_task, session_id, parent_step=orch_step)

    def run(
        self,
        query: str,
        path: str = "/",
        session_id: Optional[str] = None,
    ) -> Generator[Dict, None, None]:
        if session_id is None:
            session_id = mem.create_session(query)
        yield {"type": "session", "session_id": session_id}

        client   = self._get_client()
        system   = self._build_system(path)
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": query}
        ]
        subagent_results: Dict[str, str] = {}

        for orch_step in range(1, self.max_steps + 1):
            try:
                raw    = _ollama_call(messages, self.model_name, client, use_json=True)
                parsed = _parse_json(raw)
            except Exception as exc:
                yield {"type": "error", "message": f"Orchestrator LLM error at step {orch_step}: {exc}"}
                return

            thought = parsed.get("thought", "")
            action  = parsed.get("action",  "").strip()
            args    = parsed.get("args",    {})

            if action == "ANSWER":
                answer = parsed.get("answer") or thought
                if not isinstance(answer, str):
                    answer = json.dumps(answer, indent=2)
                mem.add_episode(session_id, orch_step, thought, "ANSWER", {}, {"answer": answer})
                yield {
                    "type":       "answer",
                    "text":       answer,
                    "session_id": session_id,
                    "steps":      orch_step,
                    "agents_used": list(subagent_results.keys()),
                }
                return

            if action == "dispatch_subagent":
                agent_id   = args.get("agent_id", "")
                sub_task   = args.get("task", query)
                sub_path   = args.get("path", path)

                yield {
                    "type":       "orchestrator_step",
                    "step":       orch_step,
                    "thought":    thought,
                    "dispatching": agent_id,
                    "task":       sub_task,
                    "path":       sub_path,
                }
                mem.add_episode(session_id, orch_step, thought, "dispatch_subagent", args, {"status": "dispatched"})

                sub_answer = "(no answer)"
                for event in self._dispatch(agent_id, sub_task, sub_path, session_id, orch_step):
                    yield event
                    if event.get("type") == "subagent_result":
                        sub_answer = event.get("answer", "(no answer)")

                subagent_results[agent_id] = sub_answer
                messages.append({"role": "assistant", "content": raw})
                messages.append({
                    "role": "user",
                    "content": f"Sub-agent '{agent_id}' completed.\n\nFINDINGS:\n{_truncate(sub_answer)}\n\nDecide: dispatch another sub-agent or synthesise ANSWER."
                })
                continue

            yield {"type": "error", "message": f"Orchestrator unknown action '{action}'."}
            return

        messages.append({"role": "user", "content": "Maximum orchestration steps reached. Synthesise final report."})
        try:
            raw    = _ollama_call(messages, self.model_name, client, use_json=True)
            parsed = _parse_json(raw)
            answer = parsed.get("answer") or parsed.get("thought", "Investigation complete.")
            if not isinstance(answer, str):
                answer = json.dumps(answer, indent=2)
        except Exception as e:
            answer = f"Could not generate final answer: {e}"

        yield {
            "type":        "answer",
            "text":        answer,
            "session_id":  session_id,
            "steps":       self.max_steps,
            "agents_used": list(subagent_results.keys()),
        }


# ── Singleton ──────────────────────────────────────────────────────────────────

_orchestrator: Optional[OrchestratorAgent] = None


def get_orchestrator() -> OrchestratorAgent:
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = OrchestratorAgent()
    return _orchestrator
