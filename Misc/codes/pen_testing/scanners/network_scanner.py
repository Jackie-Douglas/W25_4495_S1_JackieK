import subprocess

NMAP_COMMANDS = {
    "ping_scan": {
        "command": "nmap -sn {target}",
        "description": "Performs a simple ping scan to discover live hosts."
    },
    "quick_scan": {
        "command": "nmap -T4 -F {target}",
        "description": "Runs a fast scan with fewer ports to quickly identify open services."
    },
    "full_scan": {
        "command": "nmap -p- -sV -O -A {target}",
        "description": "Performs a comprehensive scan, identifying OS, services, and vulnerabilities."
    },
    "os_detection": {
        "command": "nmap -O {target}",
        "description": "Attempts to detect the operating system running on the target."
    },
    "service_version": {
        "command": "nmap -sV {target}",
        "description": "Detects service versions running on open ports."
    },
    "vuln_scan": {
        "command": "nmap --script vuln {target}",
        "description": "Runs a general vulnerability scan using Nmap scripts."
    },
    "eternalblue": {
        "command": "nmap --script smb-vuln-ms17-010 -p 445 {target}",
        "description": "Checks if the target is vulnerable to MS17-010 (EternalBlue)."
    },
    "ms08_067": {
        "command": "nmap --script smb-vuln-ms08-067 -p 445 {target}",
        "description": "Tests for the SMB vulnerability exploited by Conficker."
    },
    "rdp_vuln": {
        "command": "nmap --script rdp-vuln-ms12-020 -p 3389 {target}",
        "description": "Detects the RDP vulnerability MS12-020."
    }
}

def run_network_scan(target, selected_scans):
    results = {}
    for scan in selected_scans:
        command = NMAP_COMMANDS.get(scan, {}).get("command", "").format(target=target)
        if command:
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            results[scan] = {
                "description": NMAP_COMMANDS[scan]["description"],
                "output": result.stdout
            }
    return results

