from src.osforensics.agent_core import InvestigationAgent
import sys

def test_agent():
    agent = InvestigationAgent()
    query = "List the files in the current directory."
    print(f"Testing agent with query: {query}")
    try:
        for event in agent.run(query):
            print(event)
    except Exception as e:
        print(f"Agent failed with error: {e}")

if __name__ == "__main__":
    test_agent()
