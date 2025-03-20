import subprocess
import json
from ollama import generate_analysis

WEB_SCANS = {
    "Basic Scan": {
        "command": "nikto -h {target}",
        "description": "Performs a basic scan for common vulnerabilities in web applications."
    },
    "SSL Scan": {
        "command": "nikto -h https://{target}",
        "description": "Checks for SSL/TLS misconfigurations and vulnerabilities."
    },
    "SQL Injection": {
        "command": "nikto -h {target} -Tuning 6",
        "description": "Scans for SQL Injection vulnerabilities in web applications."
    },
    "XSS Scan": {
        "command": "nikto -h {target} -Tuning 4",
        "description": "Checks for Cross-Site Scripting (XSS) vulnerabilities."
    },
    "Headers Scan": {
        "command": "nikto -h {target} -Tuning 9",
        "description": "Analyzes HTTP headers for security misconfigurations."
    }
}

def run_scan(target, selected_scans):
    results = {}
    for scan in selected_scans:
        if scan in WEB_SCANS:
            cmd = WEB_SCANS[scan]["command"].format(target=target)
            try:
                output = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as e:
                output = e.output
            
            analysis = generate_analysis(f"Analyze the results of {scan} and suggest remediations:", output)
            results[scan] = {
                "description": WEB_SCANS[scan]["description"],
                "output": output,
                "analysis": analysis
            }

    with open("web_results.json", "w") as f:
        json.dump(results, f, indent=4)

    return results

