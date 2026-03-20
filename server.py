from fastmcp import FastMCP
import subprocess
import shlex
import re


# Initialize the MCPP Server
# Creates your MCP server instance with name "Security-Arsenal"
mcp = FastMCP("Security-Arsenal")

def is_valid_target(target):
    return re.match(r"^[a-zA-Z0-9\.\-:/]+$", target)


@mcp.tool()
def run_nmap(target: str) -> str:
    """
    Run a fast Nmap scan to find open port.
    Target can be IP (192.168.1.1) or hostname (example.com)
    """
    # -F is a "Fast mode" (scans fewer ports)
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
        return {"error": f"Nmap Error: {str(e)}"}


@mcp.tool()
def run_nuclei(target_url: str) -> str:
    """
    Run Nuclei vulnerability scanner against a URL.
    """
    # -silent removes branding/banner to make the output easier for AI to read
    if not is_valid_target(target_url):
        return {"error": "Invalid URL format"}
    
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
         return {"error": f"Nuclei Error: {str(e)}"}
    
@mcp.tool()
def manual_probe_headers(url: str) -> str:
    """
    Uses Curl to fetch HTTP headers to identify server tech.
    """
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
         return {"error": f"Curl Error: {str(e)}"}

# Run this code only when the file is executed directly.
if __name__ == "__main__":
    mcp.run()
