from flask import Flask, render_template, request, jsonify
import subprocess
import threading
import datetime

app = Flask(__name__)

# Global dictionaries to store scan results and statuses
scan_results = {
    "network": [],
    "web": []
}
scan_status = {
    "network": {},
    "web": {}
}

# Installation status tracking
install_status = {"completed": False, "progress": 0, "error": None}

def run_scan(commands, category, scan_type):
    """Runs the provided scanning commands in sequence and updates progress."""
    start_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    scan_status[scan_type][category] = {"progress": 0, "start_time": start_time, "end_time": "Running"}
    total_cmds = len(commands)
    results = []

    for index, cmd in enumerate(commands):
        process = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        results.append(f"Command: {cmd}\nOutput:\n{process.stdout}\nError:\n{process.stderr}")
        scan_status[scan_type][category]["progress"] = int(((index + 1) / total_cmds) * 100)
    
    end_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    scan_status[scan_type][category]["end_time"] = end_time
    scan_results[scan_type].append({"category": category, "results": results})

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

        # Capture error output
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

@app.route('/install', methods=['GET', 'POST'])
def install():
    """Handles installation process."""
    if request.method == 'POST':
        if not install_status["completed"]:
            threading.Thread(target=install_dependencies, daemon=True).start()
            return jsonify({"status": "Installing...", "progress": install_status["progress"]})
        return jsonify({"status": "Already Installed", "progress": 100})
    
    return render_template('install.html', install_status=install_status)

@app.route('/install/status')
def install_status_api():
    """API endpoint to check installation status."""
    return jsonify(install_status)

@app.route('/network_scan', methods=['GET', 'POST'])
def network_scan():
    """Handles network scanning."""
    if request.method == 'POST':
        selected_categories = request.json.get('categories', [])
        commands = {
            "Full Scan": ["nmap -p- -sV -O -A <target>"]
        }
        for category in selected_categories:
            if category in commands:
                threading.Thread(target=run_scan, args=(commands[category], category, "network"), daemon=True).start()
        return jsonify({"status": "Scanning started"})
    
    return render_template('network_scan.html', scan_status=scan_status['network'])

@app.route('/web_scan', methods=['GET', 'POST'])
def web_scan():
    """Handles web scanning."""
    if request.method == 'POST':
        selected_categories = request.json.get('categories', [])
        commands = {
            "Basic Scan": ["nikto -h <target-url>"]
        }
        for category in selected_categories:
            if category in commands:
                threading.Thread(target=run_scan, args=(commands[category], category, "web"), daemon=True).start()
        return jsonify({"status": "Scanning started"})
    
    return render_template('web_scan.html', scan_status=scan_status['web'])

@app.route('/results')
def results():
    """Displays scan results."""
    return render_template('results.html', results=scan_results)

if __name__ == '__main__':
    app.run(debug=True)

