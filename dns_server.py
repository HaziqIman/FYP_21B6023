import sqlite3
import socketserver
from dnslib import DNSRecord, RR, A
import os

CATEGORY_DB_PATH = "urldb_files"

# Function to check if a domain is blocked
def is_url_blocked(domain):
    for db_name in os.listdir(CATEGORY_DB_PATH):
        db_path = os.path.join(CATEGORY_DB_PATH, db_name)
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("SELECT 1 FROM porn_urls WHERE url = ?", (domain,))
        result = c.fetchone()
        conn.close()
        if result:
            return True  # Domain is blocked
    return False  # Domain is NOT blocked

# DNS Request Handler
class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0]
        socket = self.request[1]
        request = DNSRecord.parse(data)
        domain = str(request.q.qname).rstrip(".")

        if is_url_blocked(domain):
            print(f"❌ BLOCKED: {domain}")  # Debugging
            reply = request.reply()
            reply.add_answer(RR(domain, rdata=A("0.0.0.0"), ttl=60))  # Block the domain
        else:
            print(f"✅ ALLOWED: {domain} (Forwarding to Google DNS)")  # Debugging
            forward_response = DNSRecord.parse(DNSRecord.question(domain).send("8.8.8.8", 53))  # Forward request
            reply = forward_response

        socket.sendto(reply.pack(), self.client_address)

# Start DNS Server
if __name__ == "__main__":
    with socketserver.UDPServer(("0.0.0.0", 53), DNSHandler) as server:
        print("🟢 DNS Server Running on Port 53...")
        server.serve_forever()


