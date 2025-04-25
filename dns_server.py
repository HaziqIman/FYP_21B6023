import sqlite3, os
import socketserver
from dnslib import DNSRecord, RR, A

CATEGORY_DB_PATH = "urldb_files"

def is_url_blocked(domain):
    for db_name in os.listdir(CATEGORY_DB_PATH):
        conn = sqlite3.connect(os.path.join(CATEGORY_DB_PATH, db_name))
        c = conn.cursor()
        c.execute("SELECT 1 FROM porn_urls WHERE url = ?", (domain,))
        if c.fetchone():
            conn.close()
            return True
        conn.close()
    return False

class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        req = DNSRecord.parse(data)
        qname = str(req.q.qname).rstrip(".")
        if is_url_blocked(qname):
            print(f" BLOCKED: {qname}")
            reply = req.reply()
            reply.add_answer(RR(qname, rdata=A("0.0.0.0"), ttl=60))
        else:
            print(f" ALLOWED: {qname}")
            # forward to Google DNS
            reply = DNSRecord.parse(DNSRecord.question(qname).send("8.8.8.8", 53))
        sock.sendto(reply.pack(), self.client_address)

if __name__ == "__main__":
    print(" DNS Server Running on Port 53…")
    with socketserver.UDPServer(("0.0.0.0", 53), DNSHandler) as server:
        server.serve_forever()
