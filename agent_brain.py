# This file create code all about langraph

from typing import TypedDict, List

class AgentState(TypeDict):
    target: str
    recon_results: str
    vulnerabilities_report: str


def recon_agent(state: AgentState):
    print(f"-- RECON AGENT: Scanning {state['target']} --")
    # We call the existing nmap function here
    # For now, let's assume it returns the nmap text
    result = "Nmap scan: Port 80 is open, Port 443 is open"
    return {"recon_reults": result}

def analyst_agent(state: AgentState):
    print(f"--- ANALYST AGENT: Reviewing results ---")
    recon_data = state["recon_results"]
    
    if "80" in recon_data or "443" in recon_data:
        report = "Web ports found. Running Nuclei scan..."
        # Here you would call run_nuclei()
    else:
        report = "No web services found. Scan complete."
        
    return {"vulnerability_report": report}

from langgraph.graph import StateGraph, END

# 1. Create the Graph
workflow = StateGraph(AgentState)

# 2. Add our "Nodes" (The Agents)
workflow.add_node("scout", recon_agent)
workflow.add_node("analyst", analyst_agent)

# 3. Connect them
workflow.set_entry_point("scout")
workflow.add_edge("scout", "analyst")
workflow.add_edge("analyst", END)

# 4. Compile it
app = workflow.compile()