from flask import Flask, jsonify, render_template, request, redirect, url_for, session, flash, Response
from datetime import datetime, timedelta
from threading import Timer
import tensorflow as tf
import threading, platform, cpuinfo
import numpy as np
import pandas as pd
import sqlite3, json, shutil, io
import functools, win32security, win32con, psutil, GPUtil
import ctypes, sys, webbrowser, os, time, subprocess
import matplotlib
import matplotlib.pyplot as plt

from features import (
    firewall_policies,
    firewall_logs,
    bandwidth_control,
    ips_management,
    web_filtering,
)

def init_db():
    conn = sqlite3.connect('anomalies.db')
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS anomalies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hex_data TEXT NOT NULL,
            reconstruction_error REAL NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            source_ip TEXT NOT NULL,
            destination_ip TEXT NOT NULL,
            attack_type TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS anomaly_rules (
            anomaly_id INTEGER PRIMARY KEY,
            rule_name TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            message TEXT NOT NULL
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS traffic_counts (
            id INTEGER PRIMARY KEY CHECK (id=1),
            normal_count INTEGER NOT NULL DEFAULT 0,
            anomaly_count INTEGER NOT NULL DEFAULT 0
        )
    ''')
     
    cursor.execute('SELECT COUNT(*) FROM traffic_counts')
    row_count = cursor.fetchone()[0]
    if row_count == 0:
        cursor.execute('INSERT INTO traffic_counts (id, normal_count, anomaly_count) VALUES (1, 0, 0)')

    conn.commit()
    conn.close()

init_db()



app = Flask(__name__)
app.secret_key = os.urandom(24)  
app.permanent_session_lifetime = timedelta(minutes=30)  

# ------------------------------------------
# Windows Authentication and Privilege Check
# ------------------------------------------

def windows_auth(username, password, domain=None):
    if not domain:
        domain = '.'
    try:
        token = win32security.LogonUser(
            username,
            domain,
            password,
            win32con.LOGON32_LOGON_INTERACTIVE,
            win32con.LOGON32_PROVIDER_DEFAULT
        )
        token.Close()
        return True
    except:
        return False

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    print("Requesting administrative privileges...")
    try:
        subprocess.run(
            ["powershell", "Start-Process", "python", f'"{sys.argv[0]}"', "-Verb", "RunAs"],
            creationflags=subprocess.CREATE_NO_WINDOW
        )
    except Exception as e:
        print(f"Failed to elevate privileges: {e}")
    sys.exit()


def open_browser():
    webbrowser.open("http://127.0.0.1:5000")


Timer(1, open_browser).start()



def login_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/user-active', methods=['POST'])
def user_active():
    if 'user_id' not in session:
        return jsonify({'status': 'expired'}), 401  # Use 401 Unauthorized

    session['last_activity'] = datetime.utcnow().isoformat()
    return '', 204



@app.route('/')
def home():
    if 'logged_in' in session:
        return redirect(url_for('firewall_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        full_username = request.form['username']
        password = request.form['password']
        
        if "\\" in full_username:
            domain, username = full_username.split("\\", 1)
        else:
            domain = "."
            username = full_username
        
        if windows_auth(username, password, domain=domain):
            session.clear()  
            session.permanent = True 
            session['logged_in'] = True
            session['username'] = full_username
            session['last_activity'] = datetime.utcnow()  

            firewall_logs.add_login_event(full_username)

            return redirect(url_for('firewall_dashboard'))
        else:
            return render_template('login.html', error='Invalid Windows credentials. Please try again.')
    return render_template('login.html')

@app.route('/api/login_events')
@login_required
def api_login_events():
    return jsonify(firewall_logs.get_login_events())

def collect_hardware_info():
    disk = psutil.disk_usage('/')
    cpu_info = cpuinfo.get_cpu_info()
    
    def get_gpu_name():
        # Check for NVIDIA GPUs first
        gpus = GPUtil.getGPUs()
        if gpus:
            return gpus[0].name

        # Fallback to WMIC
        try:
            output = subprocess.check_output("wmic path win32_videocontroller get name", shell=True)
            lines = output.decode().split("\n")
            gpus = [line.strip() for line in lines[1:] if line.strip()]
            
            # Filter out known virtual/display-only drivers
            blacklist = ["Parsec", "RemoteFX", "Microsoft Basic Display", "VBox", "VMware"]
            filtered = [gpu for gpu in gpus if not any(v in gpu for v in blacklist)]
            
            return filtered[0] if filtered else gpus[0] if gpus else "No GPU found"
        except Exception as e:
            return f"GPU detection error: {e}"



    info = {
        # Typically cpu_info['brand_raw'] gives a nice CPU name
        'cpu': cpu_info.get('brand_raw', 'Unknown CPU'),
        
        'ram_gb': round(psutil.virtual_memory().total / (1024 ** 3), 2),
        'storage_total_gb': round(disk.total / (1024 ** 3), 2),
        'storage_used_gb': round(disk.used / (1024 ** 3), 2),
        'storage_free_gb': round(disk.free / (1024 ** 3), 2),
        'gpu': get_gpu_name()
    }
    return info



@app.route('/firewall-dashboard')
@login_required
def firewall_dashboard():
    from features.firewall_policies import get_firewall_policies
    policies = get_firewall_policies()
    # for p in policies:
    #     print("DEBUG Policy:", p)
    total_count = len(policies)
    allowed_count = sum(
        1 for p in policies
        if p.get('Action', '').strip() == 'Allow'
    )
    blocked_count = sum(
        1 for p in policies
        if p.get('Action', '').strip() == 'Block'
    )
    enabled_count = sum(
        1 for p in policies
        if p.get('Enabled', '').strip() == 'Yes'
    )
    disabled_count = sum(
        1 for p in policies
        if p.get('Enabled', '').strip() == 'No'
    )

    dns_info = get_dns_status()
    top_attacks = ips_management.get_top_attack_types(limit=5)
    top_attacks_enumerated = [(i+1, attack, count) for i, (attack, count) in enumerate(top_attacks)]

    hardware_info = collect_hardware_info()


    firewall_logs = get_logs()
    
    # Aggregate logs by date (YYYY-MM-DD format)
    log_counts = {}
    for log in firewall_logs:
        # Assumes log["timestamp"] is formatted as "YYYY-MM-DD HH:MM:SS"
        date = log["timestamp"].split(" ")[0]
        log_counts[date] = log_counts.get(date, 0) + 1

    # Determine the "spike" day (the date with the most logs)
    if log_counts:
        spike_date = max(log_counts, key=log_counts.get)
        spike_count = log_counts[spike_date]
    else:
        spike_date = "N/A"
        spike_count = 0

    # Prepare data for the chart: sort the dates for display purposes.
    sorted_dates = sorted(log_counts.keys())
    sorted_counts = [log_counts[date] for date in sorted_dates]

    return render_template(
        'Firewall_Dashboard.html',
        policy_count=total_count,
        allowed_count=allowed_count,
        blocked_count=blocked_count,
        enabled_count=enabled_count,
        disabled_count=disabled_count,
        dns_info=dns_info,
        current_email=ips_management.user_email,
        top_attacks_enumerated=top_attacks_enumerated,
        hardware_info=hardware_info,
        labels=sorted_dates,
        counts=sorted_counts,
        spike_date=spike_date,
        spike_count=spike_count
    )


@app.route('/logout')
def logout():
    session.clear()  
    return redirect(url_for('login'))

@app.route('/start-monitoring')
def start_monitoring_route():
    ips_management.anomalous_packets = []  
    threading.Thread(target=ips_management.start_monitoring, daemon=True).start()
    return jsonify({'status': 'started'})

@app.route('/stop-monitoring')
def stop_monitoring_route():
    ips_management.stop_monitoring()
    return jsonify({'status': 'stopped'})

@app.route('/get-anomalies')
def get_anomalies_route():
    anomalies = ips_management.get_anomalies()
    return jsonify({'anomalies': anomalies})

@app.route('/unblock-packet', methods=['POST'])
def unblock_packet_endpoint():
    """
    Unblock the IP by looking up the rule in the DB and calling netsh delete rule.
    Expects JSON:
    {
      "source_ip": "...",
      "destination_ip": "..."
    }
    """
    data = request.json
    source_ip = data.get('source_ip')
    destination_ip = data.get('destination_ip')

    if not source_ip or not destination_ip:
        return jsonify({'error': 'Source IP or Destination IP is missing.'}), 400

    result = ips_management.unblock_packet(source_ip, destination_ip)
    if 'error' in result:
        return jsonify(result), 400
    return jsonify(result)


from features.firewall_policies import get_firewall_policies, add_firewall_policy, disable_firewall_policy, delete_firewall_policy

@app.route('/api/firewall_policies', methods=['GET'])
def firewall_policies():
    policies = get_firewall_policies()
    return jsonify(policies)

from features.firewall_logs import add_log_entry, get_logs, add_web_filter_log_entry, get_web_filter_logs

@app.route('/api/add_firewall_policy', methods=['POST'])
def add_firewall_policy_route():
    data = request.json
    print(f"Received data: {data}") 
    
    rule_name = data.get("rule_name")
    print(f"Extracted rule_name: {rule_name}") 
    
    result = add_firewall_policy(data)
    if result["success"]:
        add_log_entry("Added", rule_name)
        return jsonify({"success": True})
    else:
        return jsonify({"success": False, "message": result["message"]}), 500

@app.route('/api/disable_firewall_policy', methods=['POST'])
def disable_firewall_policy_route():
    data = request.json
    rule_name = data.get('rule_name')
    if not rule_name:
        return jsonify({"success": False, "message": "Missing rule_name"}), 400

    result = disable_firewall_policy(rule_name)
    if result["success"]:
        add_log_entry("Disabled", rule_name)
        return jsonify({"success": True})
    else:
        return jsonify({"success": False, "message": result["message"]}), 500

@app.route('/api/delete_firewall_policy', methods=['POST'])
def delete_firewall_policy_route():
    data = request.json
    rule_name = data.get('rule_name')
    if not rule_name:
        return jsonify({"success": False, "message": "Missing rule_name"}), 400

    result = delete_firewall_policy(rule_name)
    if result["success"]:
        add_log_entry("Deleted", rule_name)
        return jsonify({"success": True})
    else:
        return jsonify({"success": False, "message": result["message"]}), 500

@app.route('/api/get_firewall_logs', methods=['GET'])
def get_firewall_logs_route():
    logs = get_logs()
    return jsonify(logs)

@app.route('/get-bandwidth-usage', methods=['GET'])
def get_bandwidth_usage():
    data = bandwidth_control.get_current_bandwidth_usage()
    return jsonify(data)

from features.bandwidth_control import get_gpu_temperature, get_disk_usage, get_cpu_processes, get_memory_processes, get_gpu_processes
@app.route('/metrics')
def metrics():
    cpu_usage = psutil.cpu_percent(interval=1)
    mem_usage = psutil.virtual_memory().percent
    disk_usage = get_disk_usage()
    gpu_temp = get_gpu_temperature()

    gpu_usage = sum(gpu.load * 100 for gpu in GPUtil.getGPUs()) / len(GPUtil.getGPUs()) if GPUtil.getGPUs() else 0
    
    return jsonify(
        cpu=cpu_usage,
        gpu=round(gpu_usage, 2),
        memory=mem_usage,
        disk=disk_usage,
        gpu_temp=gpu_temp
    )

@app.route('/processes/cpu')
def processes_cpu():
    processes = get_cpu_processes()
    return jsonify(processes=processes)

@app.route('/processes/memory')
def processes_memory():
    processes = get_memory_processes()
    return jsonify(processes=processes)

@app.route('/processes/gpu')
def processes_gpu():
    processes = get_gpu_processes()
    return jsonify(processes=processes)


from features.web_filtering import block_url, unblock_url

# -------------------------------
# Web Filtering Routes 
# -------------------------------
@app.route('/apply-filter', methods=['POST'])
def apply_filter():
    url = request.form.get('filter-url')
    action = request.form.get('filter-action')
    name = request.form.get('filter-name')
    
    if action == 'block':
        block_url(url, is_admin)
        add_web_filter_log_entry("Blocked", name, url)
        return jsonify({"status": "success", "message": f"Successfully blocked {url}"})
    
    flash("Action not supported", "error")
    return redirect(url_for('firewall_dashboard'))

@app.route('/unblock-url/<url>', methods=['POST'])
def unblock(url):
    name = request.form.get('filter-name')
    unblock_url(url, is_admin)
    add_web_filter_log_entry("Blocked", name, url)
    return jsonify({"status": "success", "message": f"Successfully unblocked {url}"})

@app.route('/api/get_webfilter_logs', methods=['GET'])
def get_web_logs_route():
    logs = get_web_filter_logs()
    return jsonify(logs)


CATEGORY_DB_PATH = "urldb_files"

def is_domain_blocked(domain):
    for db_name in os.listdir(CATEGORY_DB_PATH):
        db_path = os.path.join(CATEGORY_DB_PATH, db_name)
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("SELECT 1 FROM blocked_urls WHERE url = ?", (domain,))
        result = c.fetchone()
        conn.close()
        if result:
            return True  
    return False

@app.route("/apply-rules", methods=["POST"])
def apply_rules():
    data = request.json
    for category, action in data.items():
        if action == "block":
            print(f"Blocking category: {category}") 
        else:
            print(f"Allowing category: {category}")  

    return jsonify({"message": "Rules applied successfully"}), 200

@app.route("/check", methods=["POST"])
def check():
    data = request.json
    domain = data.get("domain")
    if is_domain_blocked(domain):
        return jsonify({"status": "blocked"}), 403
    return jsonify({"status": "allowed"}), 200



def set_dns(dns_server):
    """Sets the system DNS to a specified server or resets it to automatic."""
    try:
        command = 'netsh interface show interface'
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        output_lines = result.stdout.splitlines()

        interface = None
        for line in output_lines:
            columns = line.split()
            if len(columns) < 4:
                continue  # Skip invalid lines

            admin_state, state, type_, interface_name = columns[0], columns[1], columns[2], " ".join(columns[3:])
            
            if state == "Connected":  # Ensure it is exactly "Connected"
                if "Wi-Fi" in interface_name or "Wireless" in interface_name:
                    interface = interface_name  # Capture full Wi-Fi name
                    break  # Prefer Wi-Fi if found
                elif "Ethernet" in interface_name:
                    interface = interface_name  # Capture the correct Ethernet name

        if not interface:
            return {"success": False, "message": "No active network interface detected."}

        if dns_server == "auto":
            command = f'netsh interface ip set dns name="{interface}" dhcp'
            message = f"DNS reset to automatic for {interface}"
        else:
            command = f'netsh interface ip set dns name="{interface}" static {dns_server}'
            message = f"DNS set to {dns_server} for {interface}"

        subprocess.run(command, shell=True, check=True)
        return {"success": True, "message": message}

    except Exception as e:
        return {"success": False, "message": f"Error: {str(e)}"}


@app.route("/toggle-dns", methods=["POST"])
def toggle_dns():
    data = request.get_json()
    action = data.get("action")

    if action == "on":
        result = set_dns("127.0.0.1")
    elif action == "off":
        result = set_dns("auto")
    else:
        return jsonify({"success": False, "message": "Invalid action."})

    return jsonify(result)

def get_dns_status():
    """
    Returns { "interface": <str>, "dns_server": <str>, "status": "Active" or "Inactive" }
    DNS is "Active" only if it's set to 127.0.0.1; otherwise it's "Inactive".
    """
    try:
        # 1) Find the currently connected interface
        command = 'netsh interface show interface'
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        output_lines = result.stdout.splitlines()

        interface = None
        for line in output_lines:
            columns = line.split()
            if len(columns) < 4:
                continue  # skip short lines

            admin_state, state, type_, interface_name = columns[0], columns[1], columns[2], " ".join(columns[3:])
            if state == "Connected":
                if "Wi-Fi" in interface_name or "Wireless" in interface_name:
                    interface = interface_name
                    break  # prioritize Wi-Fi
                elif "Ethernet" in interface_name:
                    interface = interface_name
                    # no break, in case Wi-Fi shows up further down

        if not interface:
            return {
                "interface": None,
                "dns_server": "None",
                "status": "Inactive"
            }

        # 2) Check whether DNS is static or DHCP
        # Using "netsh interface ip show addresses name=..."
        # (You can also use "netsh interface ip show dns" if you prefer.)
        command = f'netsh interface ip show addresses name="{interface}"'
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)

        # We'll look for "DHCP enabled: Yes" => auto
        # or an assigned DNS server line containing 127.0.0.1, etc.
        dns_server = None

        # If "DHCP enabled: Yes" => auto
        if "DHCP enabled: Yes" in result.stdout:
            dns_server = "auto"
        else:
            # Otherwise, parse for a line containing "DNS Servers" or an IP
            for line in result.stdout.splitlines():
                ip_line = line.strip()
                # If a line starts with digits and looks like an IP
                if ip_line and ip_line[0].isdigit() and "." in ip_line:
                    dns_server = ip_line
                    break
        
        if not dns_server:
            # If we didn't find anything, assume auto
            dns_server = "auto"

        # 3) Status is "Active" only if it's exactly "127.0.0.1"
        if dns_server == "127.0.0.1":
            status = "Active"
        else:
            # auto or any other static IP => "Inactive" by your definition
            status = "Inactive"

        return {
            "interface": interface,
            "dns_server": dns_server,
            "status": status
        }

    except Exception as e:
        return {
            "interface": None,
            "dns_server": "Error",
            "status": f"Error: {e}"
        }



# ips_management.user_email = "example@gmail.com"

@app.route('/set_email', methods=['POST'])
def set_email():
    data = request.get_json()
    email = data.get('email')
    if email:
        # Update the module variable
        ips_management.user_email = email

        # Update persistent storage
        config = ips_management.load_config()  # load current config
        config["user_email"] = email
        ips_management.save_config(config)

        return jsonify({'status': 'success', 'email': email})
    return jsonify({'status': 'error', 'message': 'No email provided'}), 400

@app.route('/api/stats')
def get_stats():
    import psutil
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    cpu = psutil.cpu_percent(interval=1)

    return jsonify({
        "cpu": cpu,
        "memory": {
            "used_percent": memory.percent,
            "used_gb": round(memory.used / (1024**3), 2),
            "free_percent": 100 - memory.percent,
            "free_gb": round(memory.available / (1024**3), 2),
            "total_gb": round(memory.total / (1024**3), 2),
        },
        "disk": {
            "used_percent": disk.percent,
            "used_gb": round(disk.used / (1024**3), 2),
            "free_percent": 100 - disk.percent,
            "free_gb": round(disk.free / (1024**3), 2),
            "total_gb": round(disk.total / (1024**3), 2),
        }
    })



@app.route('/traffic-chart.png')
def traffic_chart():
    n_normal, n_anomaly = ips_management.get_traffic_counts()

    fig, ax = plt.subplots()
    categories = ['Normal', 'Anomaly']
    counts = [n_normal, n_anomaly]

    bars = ax.bar(categories, counts)
    bars[0].set_color('green')
    bars[1].set_color('red')

    ax.set_ylim(0, max(counts) * 1.1)

    for i, v in enumerate(counts):
        ax.text(i, v + (max(counts) * 0.01), str(v), ha='center', fontweight='bold', fontsize=20)

    # ax.set_title('Traffic Overview')
    # ax.set_ylabel('Packet Count')
    plt.tight_layout()

    buf = io.BytesIO()
    fig.savefig(buf, format='png')
    buf.seek(0)
    
    return Response(buf.getvalue(), mimetype='image/png')


def get_top_network_processes(duration=1):
    """Return a list of the top 5 processes by network I/O over `duration` seconds."""
    # sample start stats
    net_io_start = {}
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            io = proc.io_counters()
            net_io_start[proc.pid] = {
                'name': proc.info['name'],
                'sent': getattr(io, 'other', 0),
                'recv': getattr(io, 'read_bytes', 0)
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    time.sleep(duration)

    # sample end stats and compute diff
    diffs = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            io = proc.io_counters()
            start = net_io_start.get(proc.pid)
            if not start:
                continue
            sent = getattr(io, 'other', 0) - start['sent']
            recv = getattr(io, 'read_bytes', 0) - start['recv']
            total = sent + recv
            if total > 0:
                diffs.append({
                    'name': proc.info['name'],
                    'pid': proc.pid,
                    'bytes': total
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # sort & take top 5
    top5 = sorted(diffs, key=lambda x: x['bytes'], reverse=True)[:10]
    # convert bytes to kilobytes on the client or here, as you prefer
    return top5

@app.route('/top_network_usage')
def top_network_usage():
    # run with a small sampling window so the HTTP response isn't too slow
    top5 = get_top_network_processes(duration=1)
    return jsonify(top5)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)
