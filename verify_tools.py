
import sys
import os
from pathlib import Path

# Add src to sys.path
sys.path.append(os.path.abspath("src"))

from osforensics import agent_tools

def test_tool_presence():
    registry = agent_tools.TOOL_REGISTRY
    expected = [
        "analyze_multimedia",
        "analyze_tails_os",
        "audit_security_configs",
        "carve_deleted_files"
    ]
    for tool in expected:
        if tool in registry:
            print(f"✅ Tool found: {tool}")
        else:
            print(f"❌ Tool MISSING: {tool}")

def test_tool_execution_dry_run():
    # Test with a non-existent path to ensure error handling works and function is callable
    tools_to_test = [
        ("analyze_multimedia", {"path": "/tmp/non_existent_path"}),
        ("analyze_tails_os", {"path": "/tmp/non_existent_path"}),
        ("audit_security_configs", {"path": "/tmp/non_existent_path"}),
        ("carve_deleted_files", {"image_path": "/tmp/non_existent_image", "groups": ["image"]})
    ]
    
    for name, args in tools_to_test:
        print(f"Testing {name}...")
        result = agent_tools.execute_tool(name, args)
        if "error" in result:
            print(f"  Got expected error (path doesn't exist): {result['error'][:50]}...")
        else:
            print(f"  Success: {result}")

if __name__ == "__main__":
    test_tool_presence()
    test_tool_execution_dry_run()
