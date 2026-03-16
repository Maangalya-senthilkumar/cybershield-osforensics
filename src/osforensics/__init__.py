"""osforensics package (moved to src layout)

Lightweight package init for the OS Forensics prototype.
"""

from .orchestrator import OrchestratorAgent, SubAgent, get_orchestrator
from .sub_tools import (
    BROWSER_TOOLS,
    MEMORY_TOOLS,
    PERSISTENCE_TOOLS,
    FILESYSTEM_TOOLS,
    SERVICES_TOOLS,
    CONFIG_TOOLS,
    MULTIMEDIA_TOOLS,
    TAILS_TOOLS,
)

__all__ = [
    "extractor",
    "detector",
    "classifier",
    "report",
    "api",
    "timeline",
    "deleted",
    "persistence",
    "tails",
    "OrchestratorAgent",
    "SubAgent",
    "get_orchestrator",
    "BROWSER_TOOLS",
    "MEMORY_TOOLS",
    "PERSISTENCE_TOOLS",
    "FILESYSTEM_TOOLS",
    "SERVICES_TOOLS",
    "CONFIG_TOOLS",
    "MULTIMEDIA_TOOLS",
    "TAILS_TOOLS",
    "container",
]
