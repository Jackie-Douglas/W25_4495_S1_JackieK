import subprocess
import ollama
import os
from flask import Flask, request, render_template

app = Flask(__name__)

def run_nmap_scan(target, selected_scans):
    # Dictionary with scan names as keys and Nmap commands as values
    nmap_commands = {
        "Full Port Scan": f"nmap -p- -sV -O -A {target}",
        "SMB & RDP Vulnerability Scan": f"nmap --script smb-vuln-ms17-010,smb-vuln-ms08-067,smb-enum-shares,smb-enum-users,smb-os-discovery -p 445 {target}",
        "Web & FTP Vulnerability Scan": f"nmap --script http-vuln-cve2017-5638,http-vuln-cve2014-3704,http-vuln-misfortune-cookie -p 80,443 {target}",
        "SMTP & DNS Security Scan": f"nmap --script smtp-vuln-cve2011-1720,ftp-anon,samba-vuln-cve-2012-1182,dns-zone-transfer -p 21,25,53,139,445 {target}",
        "Comprehensive Vulnerability Scan": f"nmap --script vulners -sV {target}"
    }

    os.makedirs("static", exist_ok=True)
    raw_output = ""
    analysis_report = ""
    output_file = "static/net_output.txt"
    analysis_file = "static/net_analysis.html"

    for scan in selected_scans:
        command = nmap_commands.get(scan)
        if not command:
            continue

        try:
            result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, timeout=300).decode()
        except subprocess.CalledProcessError as e:
            result = e.output.decode()
        except subprocess.TimeoutExpired:
            result = f"Scan timed out for: {scan}"

        raw_output += f"\n====================\n{scan}\n====================\n"
        raw_output += f"Command: {command}\n"
        raw_output += result + "\n"

        prompt = f'''
Generate a detailed, structured, and beginner-friendly HTML report with the following layout:

===========================
🟢 <h2>{scan}</h2>
===========================

1. <h3>📝 Executive Summary</h3>
- A clear and concise overview in simple language.
- Help non-technical users understand the scan findings.
- Use icons like ✅, ⚠️, or 🔴 where appropriate.

2. <h3>📋 Detailed Analysis Table</h3>
Create an HTML table with these rows:
| Section | Description |
|--------|-------------|
| Command Used | {command} |
| Purpose | What does this command try to achieve? |
| Risks Detected | Summarize possible vulnerabilities. |
| Output Analysis | Analyze this output: \n{result} |
| Recommended Remediation | What should be done to fix the issue? |
| Severity Level | Use 🔴 High, 🟠 Medium, 🟡 Low. Include why it’s that level. |

3. <h3>📌 Visual Severity Block</h3>
Display severity level as a large colored banner:
- Red (`background-color:#ffcccc`) for High
- Orange (`background-color:#ffe5cc`) for Medium
- Yellow (`background-color:#ffffcc`) for Low

4. <h3>📖 Additional Tips & Insights</h3>
- Add expert tips or common pitfalls.
- Mention if any findings may be false positives.
- Suggest any manual investigation steps.

5. <h3>🔽 Advanced Details (Collapsible)</h3>
<p>Click to expand raw scan output:</p>
<details>
  <summary>Show Raw Output</summary>
  <pre>{result}</pre>
</details>
'''

        response = ollama.chat(model="llama3", messages=[{"role": "user", "content": prompt}])

        analysis_report += response['message']['content'] + "\n"

    with open(output_file, "w") as raw:
        raw.write(raw_output)

    with open(analysis_file, "w") as report:
        report.write(analysis_report)

    return raw_output, analysis_report

@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        target = request.form.get("target")
        selected_scans = request.form.getlist("scan_options")
        
        if not target or not selected_scans:
            return render_template("net.html", error="Please provide a target and select at least one scan option.")
        
        raw_output, analysis_report = run_nmap_scan(target, selected_scans)
        
        return render_template("net.html", scanning=True, show_complete=True)

    return render_template("net.html")

if __name__ == "__main__":
    app.run(debug=True)
