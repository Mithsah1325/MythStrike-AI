from typing import List, TypedDict
import requests
from langgraph.graph import StateGraph, END


# Import your real tools from your first file
from mcp_server import run_nmap, run_nuclei, run_sqlmap, run_subfinder, manual_probe_headers, run_ffuf

class AgentState(TypedDict):
    target: str
    subdomains: List[str]
    recon_results: str
    vulnerabilities_report: str
    poc_results: str

# --- 2. The Agents (Now using REAL tools) ---

def recon_agent(state: AgentState):
    target = state['target']
    
    # 1. Find Subdomains first
    sub_data = run_subfinder(target)
    sub_list = sub_data.get("output", "").strip().split("\n")
    print(f"[Scout]: Found {len(sub_list)} subdomains.")

    # 2. Run Nmap on the main target
    nmap_data = run_nmap(target)
    scan_text = nmap_data.get("output", "")
    
    return {
        "subdomains": sub_list,
        "recon_results": scan_text
    }
# Analyst Agent
def analyst_agent(state: AgentState):
    recon_data = state["recon_results"].lower() # Convert to lowercase to make matching easier
    target = state["target"]
    url = f"http://{target}"
    
    print(f"[Analyst]: Analyzing findings for {target}...")

    # 1. Check for Database/Injection triggers (SQLMap)
    if any(x in recon_data for x in ["sqli", "sql", "injection", "database", "mysql", "postgre", "php", "id="]):
        print("[Analyst]: Database signatures detected. Launching SQLMap...")
        result = run_sqlmap(url)
        report = result.get("output", "")
        return {"vulnerabilities_report": report}
    
    # 2. Check for Web triggers (ffuf or Nuclei)
    elif any(x in recon_data for x in ["80/tcp", "443/tcp", "http", "apache", "nginx"]):
        print("[Analyst]: Web server confirmed. Starting Directory Discovery (ffuf)...")
        
        # Run ffuf first to find hidden paths
        ffuf_result = run_ffuf(url)
        
        # Now pass the findings to Nuclei for vulnerability scanning
        print("[Analyst]: Running Nuclei to check for known exploits...")
        nuclei_result = run_nuclei(url)
        
        # Combine the results for the final report
        report = f"--- FFUF RESULTS ---\n{ffuf_result.get('output')}\n\n--- NUCLEI RESULTS ---\n{nuclei_result.get('output')}"
        return {"vulnerabilities_report": report}
    
    else:
        # Fallback: If Nmap missed it but we think it's a website, run a quick check
        print("[Analyst]: No clear web ports in Nmap, but trying Nuclei anyway as a backup...")
        result = run_nuclei(url)
        return {"vulnerabilities_report": result.get("output", "No results found.")}


# import requests

# 4. PoC Agent (Safe Validation)
# -------------------------------
def poc_agent(state: AgentState):
    report = state["vulnerabilities_report"]
    target = state["target"]
    url = f"http://{target}"

    print("[PoC Agent]: 🧪 Validating vulnerabilities...")

    findings = []
    lines = report.split("\n")

    # 4.1 SQL Injection Validation
    if any(x in report.lower() for x in ["sqli", "sql", "injection", "database"]):
        print("[PoC Agent]: Testing for SQL Injection...")
        try:
            normal = requests.get(url, timeout=5).text
            true_case = requests.get(url + "?id=1 AND 1=1", timeout=5).text
            false_case = requests.get(url + "?id=1 AND 1=2", timeout=5).text

            if true_case == normal and false_case != normal:
                findings.append("[HIGH] VERIFIED SQL Injection (Boolean-based)")
            else:
                findings.append("[MEDIUM] SQL Injection not confirmed")
        except Exception as e:
            findings.append(f"[ERROR] SQLi test failed: {str(e)}")

    # 4.2 Header Security Validation
    try:
        res = requests.get(url, timeout=5)
        headers = res.headers

        if "X-Frame-Options" not in headers:
            findings.append("[LOW] Missing X-Frame-Options (Clickjacking risk)")
        if "Content-Security-Policy" not in headers:
            findings.append("[LOW] Missing CSP header")
        if "Strict-Transport-Security" not in headers:
            findings.append("[LOW] Missing HSTS header")
        if "X-Content-Type-Options" not in headers:
            findings.append("[LOW] Missing X-Content-Type-Options")
    except Exception as e:
        findings.append(f"[ERROR] Header check failed: {str(e)}")

    # 4.3 Parse Nuclei Findings
    # SSH Issues
    if any("ssh" in line.lower() for line in lines):
        findings.append("[MEDIUM] SSH service exposed (Port 22)")
        findings.append("[MEDIUM] Weak SSH algorithms detected (per scan)")

    # CVEs
    for line in lines:
        if "CVE-" in line:
            findings.append(f"[HIGH] Potential CVE Detected → {line.strip()}")

    # Apache Detection
    if "apache" in report.lower():
        findings.append("[INFO] Apache server detected — verify version is up-to-date")

    # Open Ports Insight
    if "open" in report.lower():
        findings.append("[INFO] Open ports detected — review exposed services")

    # Fallback
    if not findings:
        findings.append("[INFO] No actionable PoC validations performed.")

    return {
        "poc_results": findings  # structured output
    }


# --- 3. The Graph (UPDATED WITH PoC AGENT) ---
workflow = StateGraph(AgentState)

workflow.add_node("scout", recon_agent)
workflow.add_node("analyst", analyst_agent)
workflow.add_node("poc", poc_agent)  # NEW NODE

workflow.set_entry_point("scout")

workflow.add_edge("scout", "analyst")
workflow.add_edge("analyst", "poc")  # analyst → poc
workflow.add_edge("poc", END)        # poc → end

app = workflow.compile()

# Main Execution
if __name__ == "__main__":
    user_target = input("Enter a target (e.g., scanme.nmap.org): ")

    initial_state = {
        "target": user_target,
        "subdomains": [],
        "recon_results": "",
        "vulnerabilities_report": "",
        "poc_results": ""   # IMPORTANT (new state field)
    }

    final_output = app.invoke(initial_state)

    print("\n" + "="*30)
    print("       FINAL SECURITY REPORT")
    print("="*30)

    print("\n--- Vulnerability Scan ---")
    print(final_output["vulnerabilities_report"])

    print("\n--- PoC Validation ---")
for item in final_output["poc_results"]:
    print(item)