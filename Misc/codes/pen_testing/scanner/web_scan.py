import subprocess
import os
import ollama

def analyze_with_ollama(command_output):
    """Analyzes web scan result using Ollama AI."""
    prompt = f"""
    Analyze the following web vulnerability scan result:

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

def run_nikto_scan(target, selected_scans):
    """Runs Nikto web application vulnerability scans and saves the output."""
    nikto_commands = {
    "Basic Scan": f"nikto -h {target}",
    "SSL Scan": f"nikto -h {target} -ssl",
    "Verbose Scan": f"nikto -h {target} -Display V",
    "XSS & SQL Injection Scan": f"nikto -h {target} -Tuning 1,6",
    "File Inclusion & RCE Scan": f"nikto -h {target} -Tuning 4,5",
    "Server Vulnerability Scan": f"nikto -h {target} -Tuning 3"
}
    
    output_file = "static/web_output.txt"
    full_output = ""

    with open(output_file, "w") as raw_output_file, open("static/web_analysis.html", "w") as analysis_file:
        for scan_name, command in nikto_commands.items():
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
    run_nikto_scan(target_ip, selected_scans)
