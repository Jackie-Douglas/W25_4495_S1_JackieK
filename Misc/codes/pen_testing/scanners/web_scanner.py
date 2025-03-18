import subprocess

NIKTO_COMMANDS = {
    "basic_scan": {
        "command": "nikto -h {target}",
        "description": "Performs a basic web server scan."
    },
    "ssl_scan": {
        "command": "nikto -h {target} -ssl",
        "description": "Checks for SSL/TLS misconfigurations."
    },
    "headers_check": {
        "command": "nikto -h {target} -Display V",
        "description": "Analyzes HTTP headers for security issues."
    },
    "dir_traversal": {
        "command": "nikto -h {target} -Tuning 1 -Display V",
        "description": "Tests for directory traversal vulnerabilities."
    },
    "sql_injection": {
        "command": "nikto -h {target} -Tuning 6",
        "description": "Attempts SQL injection attacks to identify vulnerabilities."
    },
    "file_uploads": {
        "command": "nikto -h {target} -Tuning 2",
        "description": "Searches for unrestricted file upload vulnerabilities."
    },
    "xss_scan": {
        "command": "nikto -h {target} -Tuning 4",
        "description": "Tests for cross-site scripting (XSS) vulnerabilities."
    }
}

def run_web_scan(target, selected_scans):
    results = {}
    for scan in selected_scans:
        command = NIKTO_COMMANDS.get(scan, {}).get("command", "").format(target=target)
        if command:
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            results[scan] = {
                "description": NIKTO_COMMANDS[scan]["description"],
                "output": result.stdout
            }
    return results

