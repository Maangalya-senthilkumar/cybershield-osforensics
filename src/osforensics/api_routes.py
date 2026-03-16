"""API routes for the multi-agent forensic orchestrator.

Drop-in addition to the existing api.py.
Mount this router at /api/v2/multi-agent or merge into the existing app.

Routes
------
POST   /investigate          Start a multi-agent investigation (SSE stream)
GET    /agents               List available sub-agents and their tools
POST   /agents/{agent_id}    Run a single sub-agent directly (SSE stream)
"""
from __future__ import annotations

import json
from typing import Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from .multi_agent import get_orchestrator, OrchestratorAgent, SubAgent

router = APIRouter(prefix="/api/v2/multi-agent", tags=["multi-agent"])


# ── Request models ─────────────────────────────────────────────────────────────

class InvestigateRequest(BaseModel):
    query:      str
    path:       str = "/"
    session_id: Optional[str] = None
    max_steps:  int = 10


class SubAgentRequest(BaseModel):
    task:       str
    path:       str = "/"
    session_id: Optional[str] = None
    max_steps:  int = 5


# ── SSE helpers ────────────────────────────────────────────────────────────────

def _sse(event_type: str, data: dict) -> str:
    payload = json.dumps({"event": event_type, **data}, default=str)
    return f"data: {payload}\n\n"


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.post("/investigate")
async def investigate(req: InvestigateRequest):
    """Stream a full multi-agent investigation over SSE."""

    def _stream():
        orchestrator = get_orchestrator()
        # Allow per-request max_steps override
        orchestrator.max_steps = req.max_steps
        for event in orchestrator.run(
            query      = req.query,
            path       = req.path,
            session_id = req.session_id,
        ):
            event_type = event.get("type", "event")
            yield _sse(event_type, event)
        yield _sse("done", {"message": "Investigation complete"})

    return StreamingResponse(_stream(), media_type="text/event-stream")


@router.get("/agents")
async def list_agents():
    """Return metadata for all registered sub-agents and their tools."""
    from .multi_agent.orchestrator import _SUBAGENT_DESCRIPTIONS
    from .multi_agent.sub_tools import (
        BROWSER_TOOLS, MEMORY_TOOLS, PERSISTENCE_TOOLS, FILESYSTEM_TOOLS,
        SERVICES_TOOLS, CONFIG_TOOLS, MULTIMEDIA_TOOLS, TAILS_TOOLS,
    )
    registries = {
        "browser_agent":     BROWSER_TOOLS,
        "memory_agent":      MEMORY_TOOLS,
        "persistence_agent": PERSISTENCE_TOOLS,
        "filesystem_agent":  FILESYSTEM_TOOLS,
        "services_agent":    SERVICES_TOOLS,
        "config_agent":      CONFIG_TOOLS,
        "multimedia_agent":  MULTIMEDIA_TOOLS,
        "tails_agent":       TAILS_TOOLS,
    }
    agents = []
    for agent_id, desc in _SUBAGENT_DESCRIPTIONS.items():
        tools = [
            {"name": t["name"], "description": t["description"], "params": t["params"]}
            for t in registries[agent_id].values()
        ]
        agents.append({"agent_id": agent_id, "description": desc, "tools": tools})
    return {"agents": agents}


@router.post("/agents/{agent_id}")
async def run_sub_agent(agent_id: str, req: SubAgentRequest):
    """Run a specific sub-agent directly and stream its results."""
    from .multi_agent.orchestrator import _SUBAGENT_DESCRIPTIONS, _build_model, DEFAULT_MODEL
    from .multi_agent import (
        BROWSER_TOOLS, MEMORY_TOOLS, PERSISTENCE_TOOLS, FILESYSTEM_TOOLS,
        SERVICES_TOOLS, CONFIG_TOOLS, MULTIMEDIA_TOOLS, TAILS_TOOLS,
    )
    registries = {
        "browser_agent":     BROWSER_TOOLS,
        "memory_agent":      MEMORY_TOOLS,
        "persistence_agent": PERSISTENCE_TOOLS,
        "filesystem_agent":  FILESYSTEM_TOOLS,
        "services_agent":    SERVICES_TOOLS,
        "config_agent":      CONFIG_TOOLS,
        "multimedia_agent":  MULTIMEDIA_TOOLS,
        "tails_agent":       TAILS_TOOLS,
    }

    if agent_id not in registries:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown agent '{agent_id}'. Available: {list(registries)}",
        )

    from . import agent_memory as mem

    def _stream():
        session_id = req.session_id or mem.create_session(req.task)
        yield _sse("session", {"session_id": session_id})

        try:
            model = _build_model(DEFAULT_MODEL)
        except EnvironmentError as e:
            yield _sse("error", {"message": str(e)})
            return

        sub = SubAgent(
            agent_id      = agent_id,
            description   = _SUBAGENT_DESCRIPTIONS.get(agent_id, "Specialist agent"),
            tool_registry = registries[agent_id],
            model         = model,
            max_steps     = req.max_steps,
        )
        full_task = f"{req.task}\n\nFilesystem/dump path: {req.path}"
        for event in sub.run(full_task, session_id, parent_step=0):
            yield _sse(event.get("type", "event"), event)
        yield _sse("done", {"message": f"{agent_id} complete"})

    return StreamingResponse(_stream(), media_type="text/event-stream")
