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

        raw_output += f"\n====================\n{scan}\n====================\n\n"
        raw_output += f"Command: {command}\n\n"
        raw_output += result + "\n"

        prompt = f'''
Generate a detailed, structured, and beginner-friendly HTML report with the following layout:
<style>
  body {{
    font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
    background-color: #f9f9f9;
    color: #333;
    line-height: 1.6;
    padding: 20px;
  }}
  h2 {{
    background-color: #222;
    color: #fff;
    padding: 10px 15px;
    border-radius: 8px;
  }}
  h3 {{
    color: #006666;
    margin-top: 30px;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 15px;
  }}
  table, th, td {{
    border: 1px solid #ccc;
  }}
  th, td {{
    padding: 10px;
    text-align: left;
  }}
  th {{
    background-color: #f2f2f2;
  }}
  .severity-block {{
    font-size: 1.2em;
    font-weight: bold;
    text-align: center;
    padding: 20px;
    border-radius: 10px;
    margin: 20px 0;
  }}
  .severity-high {{
    background-color: #ffcccc;
    color: #b30000;
  }}
  .severity-medium {{
    background-color: #ffe5cc;
    color: #cc6600;
  }}
  .severity-low {{
    background-color: #ffffcc;
    color: #999900;
  }}
  details {{
    background-color: #f4f4f4;
    border: 1px solid #ccc;
    border-radius: 5px;
    padding: 10px;
    margin-top: 10px;
  }}
  summary {{
    font-weight: bold;
    cursor: pointer;
  }}
  pre {{
    white-space: pre-wrap;
    word-wrap: break-word;
    background-color: #fff;
    padding: 10px;
    border-radius: 5px;
    border: 1px dashed #ccc;
  }}
</style>

<h2>🔍 {scan}</h2>

<h3>📝 Executive Summary</h3>
<ul>
  <li>✅ Clear and concise overview in beginner-friendly language.</li>
  <li>⚠️ Key issues found, including their impact and suggested fix.</li>
  <li>🔴 Severity rating with icon guidance.</li>
</ul>

<h3>📋 Detailed Analysis Table</h3>
<table>
  <tr><th>Section</th><th>Description</th></tr>
  <tr><td><b>Command Used</b></td><td>{command}</td></tr>
  <tr><td><b>Purpose</b></td><td>What does this command try to achieve?</td></tr>
  <tr><td><b>Risks Detected</b></td><td>Summarize possible vulnerabilities.</td></tr>
  <tr><td><b>Output Analysis</b></td><td><pre>{result}</pre></td></tr>
  <tr><td><b>Recommended Remediation</b></td><td>What should be done to fix the issue?</td></tr>
  <tr><td><b>Severity Level</b></td><td>Use 🔴 High, 🟠 Medium, 🟡 Low. Include why it’s that level.</td></tr>
</table>

<h3>📌 Visual Severity Block</h3>
<div class="severity-block severity-high">
  🔴 High Severity – Immediate attention required.
</div>
<!-- Or use severity-medium / severity-low depending on analysis -->

<h3>📖 Additional Tips & Insights</h3>
<ul>
  <li>💡 Expert tips or common misconfigurations related to the issue.</li>
  <li>⚠️ Flag if any output might be a false positive.</li>
  <li>🔍 Suggest manual steps for deeper investigation.</li>
</ul>

<h3>🔽 Advanced Details (Collapsible)</h3>
<p>Click to expand raw scan output:</p>
<details>
  <summary>Show Raw Output</summary>
  <pre>{result}</pre>
</details>

<h3>🛠️ Remediation Methods</h3>
<p>
  Recommend remediation steps in detailed, step-by-step format:
</p>
<ol>
  <li>Identify the vulnerable service or software.</li>
  <li>Check current version and available patches.</li>
  <li>Apply vendor-recommended updates or disable the service if unnecessary.</li>
  <li>Re-scan to confirm vulnerability resolution.</li>
</ol>
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
