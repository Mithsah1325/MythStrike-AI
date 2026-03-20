from fastmcp import FastMCP
import subprocess
import shlex

# Initialize the MCPP Server
# Creates your MCP server instance with name "Security-Arsenal"
mcp = FastMCP("Security-Arsenal")

@mcp.tool()
def run_map(target: str) -> str:
    """
    Run a fast Nmap scan to find open port.
    Target can be IP (192.168.1.1) or hostname (example.com)
    """
    # -F is a "Fast mode" (scans fewer ports)
    command = ["nmap", "-F", target]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)
        return result.stdout if result.stdout else "Scan finished. No open ports found."
    except Exception as e:
        return f"Nmap Error: {str(e)}"


@mcp.tool()
def run_nuclei(target_url: str) -> str:
    """
    Run Nuclei vulnerability scanner against a URL.
    """
    # -silent removes branding/banner to make the output easier for AI to read
    command = ["nuclei", "-u", target_url, "-silent"]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=600)
        return result.stdout if result.stdout else "No vulnerabilities detected"
    except Exception as e:
        return f"Nuclei Error: {str(e)}"
    
@mcp.tool()
def manual_probe_headers(url: str) -> str:
    """
    Uses Curl to fetch HTTP headers to identify server tech.
    """
    command = ["curl", "-I", url]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        return result.stdout
    except Exception as e:
        return f"Curl Error: {str(e)}"

# Run this code only when the file is executed directly.
if __name__ == "__main__":
    mcp.run()
