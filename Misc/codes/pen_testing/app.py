from flask import Flask, render_template, request, redirect, url_for, jsonify
import subprocess
import os
import logging
from scanner.net_scan import run_nmap_scan
from scanner.web_scan import run_nikto_scan

# Initialize Flask app
app = Flask(__name__)

# Store scan status
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

@app.route('/run_installation')
def run_installation():
    commands = [
        "python3 -m venv ollama_env",
        "source ollama_env/bin/activate && sudo rm -rf /usr/local/bin/ollama ~/.ollama",
        "source ollama_env/bin/activate && curl -fsSL https://ollama.ai/install.sh | sh",
        "source ollama_env/bin/activate && ollama --version",  # Version check
        "source ollama_env/bin/activate && ollama pull llama3"
    ]

    output = []
    progress = 0

    for idx, cmd in enumerate(commands):
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, executable="/bin/bash"
        )

        # Log the raw output
        print(f"Running: {cmd}")
        print(f"STDOUT: {result.stdout}")
        print(f"STDERR: {result.stderr}")
        print(f"Return Code: {result.returncode}")

        output.append({
            "command": cmd,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "returncode": result.returncode
        })

        if result.returncode != 0:
            return jsonify({
                "status": "error",
                "message": f"Installation failed: {result.stderr}",
                "output": output
            })

        # Update progress based on the command
        progress = (idx + 1) * 20  # Each command is 20% of the total

        if cmd == "source ollama_env/bin/activate && ollama --version":
            version_output = result.stdout.strip()
            print(f"Version Output: {version_output}")  # Log the version output for debugging

            # Directly check for version format
            if not version_output.startswith("ollama version"):
                error_message = f"Unexpected output from 'ollama --version'. Output was: {version_output}"
                print(f"Error: {error_message}")
                return jsonify({
                    "status": "error",
                    "message": error_message,
                    "output": output
                })
            else:
                # Successfully retrieved version
                version_number = version_output.split("ollama version")[-1].strip()
                print(f"Ollama version: {version_number}")
        
        # Update the frontend with the current progress
        # You can send this progress to the frontend to update the progress bar

    return jsonify({
        "status": "success",
        "message": "Installation completed successfully!",
        "output": output
    })

@app.route('/check_ollama_version')
def check_ollama_version():
    try:
        # Activate the virtual environment explicitly
        venv_path = "/path/to/your/ollama_env/bin/activate_this.py"  # Adjust the path
        exec(open(venv_path).read(), {'__file__': venv_path})

        # Run the ollama version command
        result = subprocess.run(
            "ollama --version", shell=True, capture_output=True, text=True
        )

        print(f"STDOUT: {result.stdout}")
        print(f"STDERR: {result.stderr}")
        print(f"Return code: {result.returncode}")

        if result.returncode == 0:
            version_output = result.stdout.strip()
            if version_output.startswith("ollama version"):
                version_number = version_output.split("ollama version")[-1].strip()
                return jsonify({"status": "already_installed", "version": version_number})
            else:
                return jsonify({"status": "error", "message": "Unexpected version output"})
        else:
            return jsonify({"status": "error", "message": f"Failed to fetch version. Output: {result.stderr.strip()}"})

    except Exception as e:
        return jsonify({"status": "error", "message": f"An error occurred: {str(e)}"})


# Network Security Scan Page
@app.route('/network', methods=['GET', 'POST'])
def network():
    if request.method == 'POST':
        target = request.form.get('target')
        selected_scans = request.form.getlist('scan_options')

        if not selected_scans:
            return render_template('net.html', error="No scan options selected!", scanning=False, show_complete=False)

        # Call the function to start the network scan
        raw_output, analysis_report = run_nmap_scan(target, selected_scans)

        # Update scan status
        scan_status["network_scan_completed"] = True

        return render_template('net.html', scanning=False, show_complete=True, raw_output=raw_output, analysis_report=analysis_report)

    return render_template('net.html', scanning=False, show_complete=False)

# Web Application Security Scan Page
@app.route('/web', methods=['GET', 'POST'])
def web():
    if request.method == 'POST':
        target = request.form.get('target')
        selected_scans = request.form.getlist('scan_options')

        if not selected_scans:
            return render_template('web.html', error="No scan options selected!", scanning=False, show_complete=False)

        # Call the function to start the web scan
        raw_output, analysis_report = run_nikto_scan(target, selected_scans)

        # Update scan status
        scan_status["web_scan_completed"] = True

        return render_template('web.html', scanning=False, show_complete=True, raw_output=raw_output, analysis_report=analysis_report)

    return render_template('web.html', scanning=False, show_complete=False)

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

# Logging setup
logging.basicConfig(level=logging.DEBUG)

@app.route('/run_scan', methods=['POST'])
def run_scan():
    try:
        target = request.form['target']
        output, error = run_nmap(target)
        if error:
            logging.error(f"Nmap error: {error}")
        return render_template('results.html', output=output)
    except Exception as e:
        logging.error(f"Error running Nmap: {e}")
        return "Error running scan"


if __name__ == '__main__':
    app.run(debug=True)
