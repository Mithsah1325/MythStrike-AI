from fastmcp import FastMCP
import subprocess
import re
import sys
import os
from openai import OpenAI
from dotenv import load_dotenv

# ------------------ MCP SETUP ------------------

mcp = FastMCP("Security-Arsenal")

def is_valid_target(target):
    return re.match(r"^[a-zA-Z0-9\.\-:/]+$", target)


@mcp.tool()
def run_nmap(target: str) -> dict:
    if not is_valid_target(target):
        return {"error": "Invalid target format"}

    command = ["nmap", "-F", target]

    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)
        return {
            "tool": "nmap",
            "target": target,
            "output": result.stdout,
            "error": result.stderr
        }
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def run_nuclei(target_url: str) -> dict:
    if not is_valid_target(target_url):
        return {"error": "Invalid URL"}

    command = ["nuclei", "-u", target_url, "-silent"]

    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=600)
        return {
            "tool": "nuclei",
            "target": target_url,
            "output": result.stdout,
            "error": result.stderr
        }
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def manual_probe_headers(url: str) -> dict:
    if not is_valid_target(url):
        return {"error": "Invalid URL"}

    command = ["curl", "-I", url]

    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        return {
            "tool": "curl",
            "target": url,
            "headers": result.stdout,
            "error": result.stderr
        }
    except Exception as e:
        return {"error": str(e)}
    
#Added subfinder and sqlmap tools
@mcp.tool()
def run_subfinder(domain: str) -> dict:
    print(f"[RECON] Finding subdomains for {domain}")
    # -silent keeps the output clean for the AI
    command = ["subfinder", "-d", domain, "-silent"]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)
        return {"tool": "subfinder", "output": result.stdout}
    except Exception as e:
        return {"error": str(e)}
    
@mcp.tool()
def run_sqlmap(url: str) -> dict:
    print(f"--- [EXPLOIT] Checking for SQL Injection on {url} ---")
    # --batch tells sqlmap not to ask the AI questions (it chooses default 'yes')
    command = ["sqlmap", "-u", url, "--batch", "--random-agent", "--level=1"]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=600)
        return {"tool": "sqlmap", "output": result.stdout}
    except Exception as e:
        return {"error": str(e)}   


# ------------------ AI AGENT ------------------

load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

SYSTEM_PROMPT = """
You are a cybersecurity AI agent.

Available tools:
- run_nmap(target)
- run_nuclei(url)
- manual_probe_headers(url)
- run_subfinder(domain)
Rules:
- Start with nmap
- If HTTP/HTTPS found → use curl
- If web detected → use nuclei

Respond ONLY in this format:

THOUGHT: ...
ACTION: ...
INPUT: ...
"""

def ask_llm(prompt):
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ]
    )
    return response.choices[0].message.content


def parse_response(response):
    lines = response.split("\n")
    thought = action = input_value = ""

    for line in lines:
        if line.startswith("THOUGHT:"):
            thought = line.replace("THOUGHT:", "").strip()
        elif line.startswith("ACTION:"):
            action = line.replace("ACTION:", "").strip()
        elif line.startswith("INPUT:"):
            input_value = line.replace("INPUT:", "").strip()

    return thought, action, input_value


def execute_action(action, input_value):
    if action == "run_nmap":
        return run_nmap(input_value)
    elif action == "run_nuclei":
        return run_nuclei(input_value)
    elif action == "manual_probe_headers":
        return manual_probe_headers(input_value)
    else:
        return {"error": "Unknown action"}


def run_agent():
    user_input = input("Enter target (example.com): ")

    prompt = f"Scan target: {user_input}"

    for step in range(3):
        print(f"\n--- Step {step+1} ---")

        llm_response = ask_llm(prompt)
        print("\nLLM Response:\n", llm_response)

        thought, action, input_value = parse_response(llm_response)

        print(f"\n[THOUGHT]: {thought}")
        print(f"[ACTION]: {action}")
        print(f"[INPUT]: {input_value}")

        result = execute_action(action, input_value)

        print(f"\n[RESULT]: {result}")

        prompt = f"""
        Previous result:
        {result}

        What next?
        """


# ------------------ ENTRY POINT ------------------

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "agent":
        run_agent()
    else:
        mcp.run()