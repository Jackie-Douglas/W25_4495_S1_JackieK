from flask import Flask, render_template, request, jsonify
import os
import subprocess

# Importing scanner scripts
from scanner.web_scan import run_nikto_scan
from scanner.net_scan import run_nmap_scan

app = Flask(__name__)

scan_status = {
    "network_scan_completed": False,
    "web_scan_completed": False
}

install_status = {"completed": False}

# Homepage
@app.route('/')
def index():
    return render_template('index.html')

# Installation Page
@app.route('/install')
def install():
    return render_template('install.html')

# Run installation commands
@app.route('/run_installation')
def run_installation():
    commands = [
        "python3 -m venv ollama_env",
        "source ollama_env/bin/activate && pip install ollama",
        "source ollama_env/bin/activate && ollama pull llama3"
    ]

    output = []
    for cmd in commands:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, executable="/bin/bash"
        )

        output.append({
            "command": cmd,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "returncode": result.returncode
        })

        print(f"Running: {cmd}")
        print(f"STDOUT: {result.stdout}")
        print(f"STDERR: {result.stderr}")
        print(f"Return Code: {result.returncode}")

        if result.returncode != 0:
            return jsonify({
                "status": "error",
                "message": f"Installation failed: {result.stderr}",
                "output": output
            })

    return jsonify({
        "status": "success",
        "message": "Installation completed successfully!",
        "output": output
    })


# Network Security Scan Page
@app.route('/network', methods=['GET', 'POST'])
def network():
    results = ""
    analysis_report = ""

    if request.method == 'POST':
        target = request.form['target']
        selected_scans = request.form.getlist('scan_options')
        
        if not selected_scans:
            return render_template('net.html', error="No scan options selected!")

        results = run_nmap_scan(target, selected_scans)

        with open("static/net_output.txt", "w") as f:
            f.write(results)

        return render_template('net.html', 
                               net_results=results, 
                               analysis=analysis_report, 
                               show_complete=True)

    return render_template('net.html', results=results, analysis_report=analysis_report)

# Web Application Security Scan Page
@app.route('/web', methods=['GET', 'POST'])
def web():
    results = ""
    analysis_report = ""
    
    if request.method == 'POST':
        target = request.form['target']
        selected_scans = request.form.getlist('scan_options')
        
        if not selected_scans:
            return render_template('web.html', error="No scan options selected!")

        results = run_nikto_scan(target, selected_scans)

        with open("static/web_output.txt", "w") as f:
            f.write(results)

        return render_template('web.html', 
                               web_results=results, 
                               analysis=analysis_report, 
                               show_complete=True)

    return render_template('web.html', results=results, analysis_report=analysis_report)

# Results Page
@app.route('/results')
def results():
    net_results = ""
    web_results = ""

    if os.path.exists("static/net_output.txt"):
        with open("static/net_output.txt", "r") as f:
            net_results = f.read()

    if os.path.exists("static/web_output.txt"):
        with open("static/web_output.txt", "r") as f:
            web_results = f.read()

    return render_template('results.html', net_results=net_results, web_results=web_results)

# Update Blocks
@app.route("/complete/<scan_type>")
def complete_scan(scan_type):
    return render_template("index.html", completed_scan=scan_type)

@app.route('/scan_status')
def scan_status_route():
    return jsonify(scan_status)

@app.route('/update_scan_status', methods=['POST'])
def update_scan_status():
    data = request.json
    scan_status.update(data)
    return jsonify({"message": "Scan status updated"}), 200

@app.route('/reset_scan_status', methods=['POST'])
def reset_scan_status():
    global scan_status
    scan_status = {"network_scan_completed": False, "web_scan_completed": False}
    return jsonify({"message": "Scan status reset"}), 200

if __name__ == '__main__':
    app.run(debug=True)
