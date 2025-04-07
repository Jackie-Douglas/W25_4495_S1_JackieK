import subprocess
import ollama
import os

def run_nikto_scan(target, selected_scans):
    nikto_commands = {
        "Basic Scan": f"nikto -h {target}",
        "SSL Scan": f"nikto -h {target} -ssl",
        "Verbose Scan": f"nikto -h {target} -Display V",
        "XSS & SQL Injection Scan": f"nikto -h {target} -Tuning 1,6",
        "File Inclusion & RCE Scan": f"nikto -h {target} -Tuning 4,5",
        "Server Vulnerability Scan": f"nikto -h {target} -Tuning 3"
    }

    os.makedirs("static", exist_ok=True)
    raw_output = ""
    analysis_report = ""
    output_file = "static/web_output.txt"
    analysis_file = "static/web_analysis.html"

    # Ensure the scan options received from the frontend are handled
    if not selected_scans:
        raise ValueError("No scan options selected.")
    
    for scan in selected_scans:
        command = nikto_commands.get(scan)
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

        # Ask Ollama to analyze the result
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
