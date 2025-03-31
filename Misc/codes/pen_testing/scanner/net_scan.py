import subprocess
import os
import ollama

def analyze_with_ollama(command_output):
    """Analyzes command output using Ollama AI."""
    prompt = f"""
    Analyze the following network scan result:
    
    {command_output}

    Questions to answer:
    1. What does this command do?
    2. What risks does it detect?
    3. What is the analysis of the output?
    4. What remediation steps should be taken?
    5. How severe is the detected issue?

    Provide a structured report format.
    """
    response = ollama.chat(model="llama3", messages=[{"role": "user", "content": prompt}])
    return response['message']['content']

def run_nmap_scan(target, selected_scans):
    """Runs selected Nmap scans on the target and saves the output."""
    nmap_commands = {
        "Full Port Scan": f"nmap -p- -sV -O -A {target}",
        "SMB Vulnerability (MS17-010)": f"nmap --script smb-vuln-ms17-010 -p 445 {target}",
        "SMB Vulnerability (MS08-067)": f"nmap --script smb-vuln-ms08-067 -p 445 {target}",
        "RDP Vulnerability (MS12-020)": f"nmap --script rdp-vuln-ms12-020 -p 3389 {target}",
        "HTTP Vulnerability (CVE-2017-5638)": f"nmap --script http-vuln-cve2017-5638 -p 80,443 {target}",
        "FTP Vulnerability (CVE-2010-4221)": f"nmap --script ftp-vuln-cve2010-4221 -p 21 {target}",
        "SMTP Vulnerability (CVE-2011-1720)": f"nmap --script smtp-vuln-cve2011-1720 -p 25 {target}",
        "General Vulnerability Scan": f"nmap --script vulners -sV {target}",
        "DNS Zone Transfer": f"nmap --script dns-zone-transfer -p 53 {target}"
    }

    output_file = "static/net_output.txt"
    full_output = ""

    with open(output_file, "w") as raw_output_file, open("static/net_analysis.html", "w") as analysis_file:
        for scan_name, command in nmap_commands.items():
            if scan_name in selected_scans:
                result = subprocess.run(command, shell=True, capture_output=True, text=True)
                scan_output = f"### {scan_name} ###\n{result.stdout}\n\n"
                
                # Write full output to file
                raw_output_file.write(scan_output)
                full_output += scan_output  # Append to return output

                # Display full output instead of "Scan Completed"
                print(scan_output)

                analysis = analyze_with_ollama(result.stdout)
                analysis_file.write(f"<h2>{scan_name}</h2>{analysis}<hr>")

    return full_output 

if __name__ == "__main__":
    target_ip = input("Enter target IP or domain: ")
    selected_scans = list(input("Enter selected scan categories (comma-separated): ").split(", "))
    run_nmap_scan(target_ip, selected_scans)
