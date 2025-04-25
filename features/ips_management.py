import sqlite3
import numpy as np
import subprocess
import threading
import socket

from datetime import datetime

from scapy.all import sniff, IP, raw
from sklearn.preprocessing import MinMaxScaler
import tensorflow as tf
from plyer import notification
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

import joblib





model = tf.keras.models.load_model('newest_model.keras') 
stop_monitoring_flag = False 
monitor_thread = None  
scaler = MinMaxScaler()

THRESHOLD = 0.25



rf_model = joblib.load('lgbm_model.pkl')
rf_vectorizer = joblib.load('vectorizer_lgbm.pkl')





def get_anomalies():
    """
    Retrieve anomalies from the database, most recent first.
    Returns a list of dicts with keys:
      - hex_data
      - reconstruction_error
      - timestamp
      - source_ip
      - destination_ip
      - attack_type
    """
    conn = sqlite3.connect('anomalies.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT hex_data, reconstruction_error, timestamp, source_ip, destination_ip, attack_type
        FROM anomalies
        ORDER BY timestamp DESC
    ''')
    rows = cursor.fetchall()
    conn.close()

    anomalies_list = []
    for row in rows:
        anomalies_list.append({
            'hex_data': row[0],
            'reconstruction_error': row[1],
            'timestamp': row[2],
            'source_ip': row[3],
            'destination_ip': row[4],
            'attack_type': row[5] if len(row) > 5 else None
        })
    return anomalies_list

def get_local_ip():
    """
    Returns the primary IP address of the local machine.
    Note: This can vary if multiple interfaces exist.
    Adjust for your environment if needed.
    """
    return socket.gethostbyname(socket.gethostname())

LOCAL_IP = get_local_ip() 

def extract_features(hex_data):
    """Convert packet hex data to scaled features for the model."""
    hex_array = np.array([int(hex_data[i:i+2], 16) for i in range(0, len(hex_data), 2)])

    if hex_array.shape[0] < 104:
        print(f"[DEBUG] Padded packet (original len={hex_array.shape[0]})")
        padded_features = np.pad(hex_array, (0, 104 - hex_array.shape[0]), mode='constant')
    else:
        padded_features = hex_array[:104]

    scaled_features = scaler.fit_transform(padded_features.reshape(-1, 1)).flatten()
    return scaled_features

def packet_to_hex(packet):
    
    if IP in packet:
        ip_bytes = raw(packet[IP])   
        return ip_bytes.hex()
    else:
        return bytes(packet).hex()

def show_notification(source_ip, destination_ip, reconstruction_error, timestamp, attack_type=None):
    """Show a system notification when an anomaly is detected."""
    title = "🚨 Network Anomaly Detected 🚨"
    message = (
        f"🔹 Source: {source_ip}\n"
        f"🔹 Destination: {destination_ip}\n"
        f"🔹 Error: {reconstruction_error:.4f}\n"
        f"🔹 Time: {timestamp}"
    )
    if attack_type:
        message += f"\n🔹 Attack Type: {attack_type}"

    notification.notify(
        title=title,
        message=message,
        app_name="Network Monitor",
        timeout=10 
    )

import hexpacketparser

SENDGRID_API_KEY = "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"  

def send_email_alert(hex_data, source_ip, destination_ip, reconstruction_error, timestamp, user_email, attack_type=None):
    """
    Sends an email alert using SendGrid when an anomaly is detected.
    The packet is parsed using hexpacketparser.parse_packet(packet) and its details are included in the email.
    """

    attackDescriptions = {
  "DNSCat2": "A DNS tunneling tool used to establish covert channels for data exfiltration and remote control. Attack Type: Tunneling/Exfiltration. Mitigation: Monitor DNS traffic for anomalies, apply DNS filtering, and disable unnecessary DNS features.",
  "dns2tcp": "Enables TCP traffic over DNS to bypass firewall restrictions, often used for stealthy communication. Attack Type: Covert Channel. Mitigation: Inspect DNS packet payloads, enforce strict DNS usage policies, and use behavioral detection systems.",
  "Iodine": "Tunnels IPv4 traffic over DNS, allowing attackers to bypass security controls and exfiltrate data. Attack Type: Data Exfiltration. Mitigation: Block unauthorized DNS servers and inspect DNS traffic using DPI (Deep Packet Inspection).",
  "Recon": "Involves scanning and probing network services to map topology or find vulnerabilities. Attack Type: Reconnaissance. Mitigation: Employ intrusion detection systems (IDS), implement rate limiting, and monitor for scanning behavior.",
  "DoS": "Denial of Service attack that floods resources to disrupt normal service availability. Attack Type: Disruption. Mitigation: Use rate-limiting, configure firewalls for threshold protection, and leverage DDoS protection services.",
  "BruteForce": "Repeated login attempts to crack authentication credentials, commonly targeting weak accounts. Attack Type: Credential Attack. Mitigation: Implement account lockout policies, use CAPTCHA, and enforce strong password policies.",
  "Mirai": "Botnet malware targeting IoT devices to launch large-scale DDoS attacks. Attack Type: Botnet/DDoS. Mitigation: Secure IoT devices with strong credentials, update firmware, and block known botnet IPs.",
  "Web-based": "Includes attacks like XSS or SQL injection aimed at exploiting web application vulnerabilities. Attack Type: Application Layer Attack. Mitigation: Apply input validation, use web application firewalls (WAF), and follow secure coding practices.",
  "DDoS": "Distributed attack using multiple sources to overwhelm and shut down a network or service. Attack Type: Distributed Denial of Service. Mitigation: Use load balancers, traffic filtering, and subscribe to anti-DDoS services.",
  "Neris": "Malware generating command-and-control traffic to simulate botnet behavior and network infiltration. Attack Type: Malware/Botnet. Mitigation: Employ endpoint protection, monitor outbound traffic, and block C2 communication.",
  "Htbot": "Uses compromised hosts to make web requests, hiding malicious activity behind normal HTTP traffic. Attack Type: Proxy Abuse. Mitigation: Monitor abnormal HTTP requests, apply behavior-based detection, and restrict access via firewalls.",
  "Cridex": "Banking Trojan used to steal financial information and spread to other systems within a network. Attack Type: Trojan/Data Theft. Mitigation: Use email filters, keep software updated, and monitor for unauthorized financial site access.",
  "Nsis-ay": "A dropper Trojan that installs other malware components silently on the victim’s system. Attack Type: Dropper Trojan. Mitigation: Use antivirus with real-time scanning, block known malicious executables, and restrict script execution.",
  "Shifu": "Steals banking credentials, uses advanced evasion techniques, and targets Japanese financial institutions. Attack Type: Credential Theft. Mitigation: Deploy anti-malware, block malicious domains, and implement 2FA for banking systems.",
  "Zeus": "One of the most widespread banking Trojans, known for stealing login credentials through keylogging. Attack Type: Keylogger Trojan. Mitigation: Use secure browsers for banking, deploy endpoint detection and response (EDR), and keep systems patched.",
  "Miuref": "Backdoor malware that allows remote access and executes commands issued by attackers. Attack Type: Remote Access Trojan (RAT). Mitigation: Monitor outgoing connections, use host-based intrusion prevention systems (HIPS), and isolate infected machines.",
  "Geodo": "Spambot that spreads banking malware like Emotet through malicious attachments and links. Attack Type: Malware Spreader. Mitigation: Train users on phishing awareness, use attachment scanning, and block macros in documents.",
  "Virut": "Polymorphic virus used to infect executables and join victim machines to a botnet. Attack Type: Polymorphic Virus. Mitigation: Use advanced antivirus capable of heuristic analysis, and isolate infected machines immediately.",
  "Tinba": "Tiny banking Trojan focused on intercepting browser sessions to steal sensitive user data. Attack Type: Session Hijack. Mitigation: Use secure browser extensions, enforce HTTPS, and deploy sandboxing.",
  "Torrent": "P2P file-sharing over VPN, commonly used to evade detection of unauthorized content distribution. Attack Type: Bandwidth Abuse/Anonymized Sharing. Mitigation: Block P2P protocols, monitor VPN usage, and apply acceptable use policies.",
  "Spotify": "Music streaming over VPN, potentially masking bandwidth misuse or hidden data tunneling. Attack Type: Resource Misuse. Mitigation: Monitor bandwidth usage patterns, restrict unauthorized streaming apps over VPN.",
  "Vimeo": "Video streaming via VPN, which may be abused to obscure illicit traffic patterns. Attack Type: Obfuscated Streaming. Mitigation: Identify VPN usage, implement application layer filtering, and inspect encrypted traffic patterns.",
  "Youtube": "Encrypted video traffic routed through VPN, potentially used to hide malicious payload exchanges. Attack Type: Steganographic Communication. Mitigation: Perform traffic analysis, limit media streaming in sensitive networks.",
  "Netflix": "VPN-masked high-bandwidth streaming that could be misused to conceal covert data transfers. Attack Type: Bandwidth Hiding. Mitigation: Track VPN usage, block access to streaming services on protected networks.",
  "Email": "Email communication over VPN, which can be exploited for hidden phishing, malware delivery, or data leakage. Attack Type: Encrypted Communication Channel Abuse. Mitigation: Use email DLP tools, monitor VPN-linked SMTP traffic.",
  "ICQ": "Legacy messaging service over VPN, vulnerable to abuse due to outdated protocols and weak security. Attack Type: Legacy Protocol Exploitation. Mitigation: Block deprecated protocols, monitor VPN port activity.",
  "Facebook": "Social media traffic over VPN, used to bypass access controls or enable covert message exchanges. Attack Type: Access Control Evasion. Mitigation: Apply social media restrictions on enterprise networks, log VPN activity.",
  "AIM": "Obsolete messaging protocol tunneled via VPN, potentially used for undetected data exchange. Attack Type: Covert Messaging. Mitigation: Detect legacy application usage, disable unused ports, and block known AIM servers.",
  "Hangouts": "Google chat traffic over VPN, may carry encoded messages or malicious links while avoiding scrutiny. Attack Type: Hidden Communication Channel. Mitigation: Scan chat traffic for links, restrict non-approved chat platforms.",
  "Skype": "VoIP and messaging traffic over VPN, used for encrypted C2 communications or social engineering. Attack Type: C2 Channel. Mitigation: Apply VoIP filters, inspect outbound traffic, and limit VPN access to trusted sources.",
  "VoIPBuster": "Voice communication app tunneled through VPN, potentially part of anonymized botnet or fraud channels. Attack Type: VoIP Abuse. Mitigation: Log VoIP traffic usage, limit unapproved VoIP tools, apply usage policies.",
  "SFTP": "Secure file transfer over VPN, possibly used to exfiltrate data under encrypted and anonymized cover. Attack Type: Encrypted Data Exfiltration. Mitigation: Monitor file transfer sizes, log SFTP sessions, and enforce user access rules.",
  "FTPS": "Encrypted file transfer protocol through VPN, hiding unauthorized or malicious data exchanges. Attack Type: Concealed Data Movement. Mitigation: Employ DLP systems, audit transfer logs, and restrict VPN-sourced FTPS activity.",
  "Streaming": "Traffic routed through the Tor network, potentially used to mask the exfiltration of data disguised as media streams. Attack Type: Anonymized Data Flow. Mitigation: Block Tor exit nodes, analyze media traffic patterns.",
  "Browsing": "Tor-based web browsing that may be used to anonymously access restricted or illicit websites. Attack Type: Anonymous Access. Mitigation: Detect and block Tor usage, apply strict URL filtering.",
  "Chat": "Encrypted chat traffic over Tor, which can facilitate covert communication channels for cybercriminals. Attack Type: Anonymized Communication. Mitigation: Block known chat service endpoints, monitor traffic for Tor fingerprints.",
  "TraP2P": "Peer-to-peer protocols tunneled via Tor, often used to hide illegal file sharing or botnet communication. Attack Type: Hidden P2P Activity. Mitigation: Block P2P over Tor, inspect peer connection patterns, limit Tor-capable apps.",
  "VoIP": "Voice-over-IP calls through Tor, enabling anonymized conversations that may be part of criminal coordination. Attack Type: Anonymous VoIP. Mitigation: Filter VoIP protocols over Tor, disable Tor services on VoIP devices.",
  "FileTransfer": "File transfers routed via Tor, likely to evade inspection and facilitate data exfiltration or malware delivery. Attack Type: Anonymized File Transfer. Mitigation: Use DLP solutions, block Tor access, and scan all file uploads."
}

    
    
    parsed_packet_html = hexpacketparser.parse_packet(hex_data)
    
    subject = "🚨 Network Anomaly Detected!"
    html_content = f"""
    <html>
    <body>
        <h2>🚨 Network Anomaly Detected 🚨</h2>
        <p><b>🔹 Source IP:</b> {source_ip}</p>
        <p><b>🔹 Destination IP:</b> {destination_ip}</p>
        <p><b>🔹 Reconstruction Error:</b> {reconstruction_error:.4f}</p>
        <p><b>🔹 Timestamp:</b> {timestamp}</p>
    """

    
    if attack_type:
        attack_desc = attackDescriptions.get(attack_type, "N/A")
        html_content += f"<p><b>🔹 Attack Type:</b> {attack_type}</p>"
        html_content += f"<p><b>🔹 Attack Description:</b> {attack_desc}</p>"


    html_content += f"""
        <br>
        <h3>Packet Details:</h3>
        {parsed_packet_html}
        <br>
        <p>Please investigate immediately!</p>
    </body>
    </html>
    """

    message = Mail(
        from_email="haziqiman567@gmail.com",  
        to_emails=user_email,
        subject=subject,
        html_content=html_content
    )

    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)
        print(f"📧 Email alert sent to {user_email} (Status: {response.status_code})")
    except Exception as e:
        print(f"❌ Failed to send email alert via SendGrid: {e}")

def block_ip(ip_address, direction):
    """
    Create a Windows Firewall rule to block the given IP in the specified direction ('in' or 'out').
    Returns the rule name on success, or None on failure.
    """
    rule_name = f"AnomalyBlock_{direction}_{ip_address}"
    command = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}",
        f"dir={direction}",
        "action=block",
        f"remoteip={ip_address}",
        "enable=yes"
    ]
    try:
        subprocess.run(command, check=True, capture_output=True)
        print(f"Successfully created firewall rule: {rule_name}")
        firewall_logs.add_log_entry("Anomaly detected", rule_name)
        return rule_name
    except subprocess.CalledProcessError as e:
        print(f"Failed to create firewall rule: {e}\n{e.output}")
        return None

def unblock_ip(rule_name):
    """
    Delete a Windows Firewall rule by its name.
    """
    command = [
        "netsh", "advfirewall", "firewall", "delete", "rule",
        f"name={rule_name}"
    ]
    try:
        subprocess.run(command, check=True, capture_output=True)
        print(f"Successfully deleted firewall rule: {rule_name}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Failed to delete firewall rule: {e}\n{e.output}")
        return False

def unblock_packet(source_ip, destination_ip):
    """
    Looks up the anomaly in the database by source/destination,
    fetches the firewall rule name from anomaly_rules, deletes that rule,
    and if successful, removes the anomaly record from the database as well.
    Returns a message dict for Flask responses.
    """
    conn = sqlite3.connect('anomalies.db')
    cursor = conn.cursor()

    
    cursor.execute('''
        SELECT id FROM anomalies
        WHERE source_ip=? AND destination_ip=?
        ORDER BY timestamp DESC
        LIMIT 1
    ''', (source_ip, destination_ip))
    row = cursor.fetchone()

    if not row:
        conn.close()
        return {'error': 'No matching anomaly found for these IPs.'}

    anomaly_id = row[0]

    
    cursor.execute('SELECT rule_name FROM anomaly_rules WHERE anomaly_id=?', (anomaly_id,))
    rule_row = cursor.fetchone()

    if not rule_row:
        conn.close()
        return {'error': 'No firewall rule found for this anomaly.'}

    rule_name = rule_row[0]

    
    if unblock_ip(rule_name):
        
        cursor.execute('DELETE FROM anomaly_rules WHERE anomaly_id=?', (anomaly_id,))
        cursor.execute('DELETE FROM anomalies WHERE id=?', (anomaly_id,))

        conn.commit()
        conn.close()
        firewall_logs.add_log_entry("Unblocked anomaly rule", rule_name)
        return {'message': f'Successfully unblocked IP (rule: {rule_name}).'}
    else:
        conn.close()
        return {'error': 'Failed to unblock IP.'}


import json
import os

CONFIG_FILE = "config.json"

def load_config():
    """
    Loads the configuration from CONFIG_FILE.
    If the file does not exist, it creates one with a default value.
    """
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)
    else:
        
        config = {"user_email": "example@gmail.com"}
        save_config(config)
    return config

def save_config(config):
    """
    Saves the provided configuration dictionary to CONFIG_FILE.
    """
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)


config = load_config()

user_email = config.get("user_email", "example@gmail.com")

def increment_normal_count():
    conn = sqlite3.connect('anomalies.db')
    cursor = conn.cursor()

    
    cursor.execute('''
        UPDATE traffic_counts
        SET normal_count = normal_count + 1
        WHERE id=1
    ''')
    conn.commit()
    conn.close()

def increment_anomaly_count():
    conn = sqlite3.connect('anomalies.db')
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE traffic_counts
        SET anomaly_count = anomaly_count + 1
        WHERE id=1
    ''')
    conn.commit()
    conn.close()

def get_traffic_counts():
    """Returns (normal_count, anomaly_count)."""
    conn = sqlite3.connect('anomalies.db')
    cursor = conn.cursor()
    cursor.execute('SELECT normal_count, anomaly_count FROM traffic_counts WHERE id=1')
    row = cursor.fetchone()
    conn.close()
    
    if row:
        return (row[0], row[1])
    else:
        return (0, 0)

import features.firewall_logs as firewall_logs


def monitor_packets_callback(packet):
    global normal_count, anomaly_count
    """Callback for Scapy sniff. Processes a single packet for anomaly detection."""
    if stop_monitoring_flag:
        return  

    if IP not in packet:
        return  

    
    hex_data = packet_to_hex(packet)
    features = extract_features(hex_data).reshape(1, -1)
    reconstructed = model.predict(features)
    reconstruction_error = np.mean((features - reconstructed) ** 2)

    if reconstruction_error > THRESHOLD:
        increment_anomaly_count()
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        
        rf_input = rf_vectorizer.transform([hex_data]) 
        predicted_attack_type = rf_model.predict(rf_input)[0]  

        
        rule_name = None
        if source_ip == LOCAL_IP and destination_ip != "Unknown":
            
            rule_name = block_ip(destination_ip, 'out')
        elif destination_ip == LOCAL_IP and source_ip != "Unknown":
            
            rule_name = block_ip(source_ip, 'in')

        
        conn = sqlite3.connect('anomalies.db')
        cursor = conn.cursor()

        
        cursor.execute('''
            INSERT INTO anomalies
            (hex_data, reconstruction_error, timestamp, source_ip, destination_ip, attack_type)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (hex_data, reconstruction_error, timestamp, source_ip, destination_ip, predicted_attack_type))
        anomaly_id = cursor.lastrowid

        
        if rule_name:
            cursor.execute('''
                INSERT OR REPLACE INTO anomaly_rules
                (anomaly_id, rule_name)
                VALUES (?, ?)
            ''', (anomaly_id, rule_name))

        conn.commit()
        conn.close()

        
        show_notification(
            source_ip,
            destination_ip,
            reconstruction_error,
            timestamp,
            attack_type=predicted_attack_type
        )

        
        send_email_alert(
            hex_data,
            source_ip,
            destination_ip,
            reconstruction_error,
            timestamp,
            user_email,
            attack_type=predicted_attack_type
        )
    else:
        increment_normal_count()

    
def get_top_attack_types(limit=5):
    """
    Query the anomalies table to find the most frequent attack types (up to limit).
    Returns a list of tuples: [(attack_type, occurrence_count), ...].
    """
    conn = sqlite3.connect('anomalies.db')
    cursor = conn.cursor()
    cursor.execute(f'''
        SELECT attack_type, COUNT(*) as cnt
        FROM anomalies
        WHERE attack_type IS NOT NULL
        GROUP BY attack_type
        ORDER BY cnt DESC
        LIMIT {limit};
    ''')
    rows = cursor.fetchall()
    conn.close()
    
    
    return rows


def sniff_stop_filter(_):
    """Stop filter for scapy sniff."""
    return stop_monitoring_flag

def start_monitoring():
    """Start packet sniffing in a separate thread."""
    global stop_monitoring_flag, monitor_thread
    stop_monitoring_flag = False

    def _run_sniff():
        sniff(
            prn=monitor_packets_callback,
            store=False,
            stop_filter=sniff_stop_filter
        )

    monitor_thread = threading.Thread(target=_run_sniff, daemon=True)
    monitor_thread.start()
    print("Monitoring started...")

def stop_monitoring():
    """Signal the monitoring thread to stop."""
    global stop_monitoring_flag, monitor_thread
    stop_monitoring_flag = True
    if monitor_thread:
        monitor_thread.join(timeout=5)
        print("Monitoring stopped.")
        monitor_thread = None