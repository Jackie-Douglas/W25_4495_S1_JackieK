import subprocess
import json
from ollama import generate_analysis

NETWORK_SCANS = {
    "Full Scan": {
        "command": "nmap -p- -sV -O -A {target}",
        "description": "Performs a full network scan including OS detection, service versions, and aggressive mode."
    },
    "MS17-010": {
        "command": "nmap --script smb-vuln-ms17-010 -p 445 {target}",
        "description": "Detects if the target is vulnerable to EternalBlue (MS17-010), exploited in WannaCry ransomware."
    },
    "MS08-067": {
        "command": "nmap --script smb-vuln-ms08-067 -p 445 {target}",
        "description": "Detects MS08-067 vulnerability, which allows remote code execution and is used in Metasploit."
    },
    "RDP Vulnerability": {
        "command": "nmap --script rdp-vuln-ms12-020 -p 3389 {target}",
        "description": "Checks for MS12-020, a critical RDP vulnerability that allows remote exploitation."
    },
    "Vulnerabilities Scan": {
        "command": "nmap --script vulners -sV {target}",
        "description": "Uses Vulners API to detect known vulnerabilities in detected services."
    }
}

def run_scan(target, selected_scans):
    results = {}
    for scan in selected_scans:
        if scan in NETWORK_SCANS:
            cmd = NETWORK_SCANS[scan]["command"].format(target=target)
            try:
                output = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as e:
                output = e.output
            
            analysis = generate_analysis(f"Analyze the results of {scan} and suggest remediations:", output)
            results[scan] = {
                "description": NETWORK_SCANS[scan]["description"],
                "output": output,
                "analysis": analysis
            }

    with open("network_results.json", "w") as f:
        json.dump(results, f, indent=4)

    return results

