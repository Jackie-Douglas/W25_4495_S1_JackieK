from flask import Flask, render_template, request, jsonify, session
import subprocess
import threading
import datetime
import json
from scanners.network_scanner import run_scan as run_network_scan
from scanners.web_scanner import run_scan as run_web_scan

app = Flask(__name__)
app.secret_key = "super_secret_key"  # Needed for session management

# Global dictionaries to store scan results and statuses
scan_results = {
    "network": {},
    "web": {}
}
scan_status = {
    "network": {},
    "web": {}
}

install_status = {"completed": False, "progress": 0, "error": None}

def install_dependencies():
    """Installs dependencies required for the scanner and updates the status dynamically."""
    global install_status
    install_status["progress"] = 10
    install_status["error"] = None

    commands = [
        "python3 -m venv ollama_env",
        "bash -c 'source ollama_env/bin/activate && pip install ollama'",
        "bash -c 'source ollama_env/bin/activate && ollama pull llama3'"
    ]
    
    total_cmds = len(commands)
    for index, cmd in enumerate(commands):
        process = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if process.returncode != 0:
            install_status["error"] = f"Error in command: {cmd}\n{process.stderr}"
            install_status["progress"] = 0
            return
        install_status["progress"] = int(((index + 1) / total_cmds) * 100)

    install_status["completed"] = True
    install_status["progress"] = 100

@app.route('/')
def home():
    return render_template('index.html', install_status=install_status, scan_status=scan_status)

@app.route('/save_target', methods=['POST'])
def save_target():
    """Saves the target IP or domain for scanning."""
    target = request.json.get("target")
    if target:
        session["target"] = target
        return jsonify({"message": "Target saved successfully!"})
    return jsonify({"message": "Invalid target!"}), 400

@app.route('/install', methods=['POST'])
def install():
    if not install_status["completed"]:
        threading.Thread(target=install_dependencies, daemon=True).start()
        return jsonify({"status": "Installing...", "progress": install_status["progress"]})
    return jsonify({"status": "Already Installed", "progress": 100})

@app.route('/install/status')
def install_status_api():
    return jsonify(install_status)

@app.route('/network_scan', methods=['POST'])
def network_scan():
    target = session.get("target")
    if not target:
        return jsonify({"error": "No target set"}), 400

    selected_categories = request.json.get('categories', [])
    
    if not selected_categories:
        return jsonify({"error": "No scan categories selected"}), 400

    threading.Thread(target=run_network_scan, args=(target, selected_categories), daemon=True).start()
    return jsonify({"status": "Network scan started"})

@app.route('/web_scan', methods=['POST'])
def web_scan():
    target = session.get("target")
    if not target:
        return jsonify({"error": "No target set"}), 400

    selected_categories = request.json.get('categories', [])

    if not selected_categories:
        return jsonify({"error": "No scan categories selected"}), 400

    threading.Thread(target=run_web_scan, args=(target, selected_categories), daemon=True).start()
    return jsonify({"status": "Web scan started"})

@app.route('/results')
def results():
    with open("network_results.json", "r") as f:
        scan_results["network"] = json.load(f)

    with open("web_results.json", "r") as f:
        scan_results["web"] = json.load(f)

    return render_template('results.html', results=scan_results)

if __name__ == '__main__':
    app.run(debug=True)

