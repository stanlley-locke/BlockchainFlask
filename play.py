import socket, threading, sqlite3, time, json, os, base64, hashlib
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import stun  # from pystun3

# === CONFIG ===
DB_FILE = "network.db"
BUFFER = 4096
SHARED_KEY = b"supersecurekey123"
STUN_SERVER = ("stun.l.google.com", 19302)

# === CRYPTO HELPERS ===
def derive_key(password):
    salt = b"static_salt"
    kdf = PBKDF2HMAC(algorithm=hashlib.sha256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    return kdf.derive(password)

def encrypt(msg):
    key = derive_key(SHARED_KEY)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(msg.encode()) + encryptor.finalize()
    return base64.b64encode(iv + encrypted).decode()

def decrypt(msg):
    key = derive_key(SHARED_KEY)
    raw = base64.b64decode(msg.encode())
    iv, data = raw[:16], raw[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return (decryptor.update(data) + decryptor.finalize()).decode()

# === DATABASE ===
db = sqlite3.connect(DB_FILE, check_same_thread=False)
cur = db.cursor()
cur.execute('''CREATE TABLE IF NOT EXISTS peers (
    ip TEXT, port INTEGER, trust INTEGER DEFAULT 0,
    last_seen TIMESTAMP, PRIMARY KEY(ip, port)
)''')
db.commit()
PEERS = {}
LOCK = threading.Lock()

def add_peer(ip, port):
    with LOCK:
        PEERS[(ip, port)] = time.time()
        cur.execute("INSERT OR IGNORE INTO peers (ip, port, trust, last_seen) VALUES (?, ?, 0, ?)", (ip, port, time.time()))
        cur.execute("UPDATE peers SET last_seen=? WHERE ip=? AND port=?", (time.time(), ip, port))
        db.commit()

def increment_trust(ip, port):
    cur.execute("UPDATE peers SET trust = trust + 1 WHERE ip=? AND port=?", (ip, port))
    db.commit()

def get_all_peers():
    cur.execute("SELECT ip, port, trust FROM peers")
    return cur.fetchall()

# === MESSAGING ===
def encode_packet(type_, payload):
    return json.dumps({"type": type_, "payload": encrypt(json.dumps(payload))}).encode()

def decode_packet(data):
    try:
        obj = json.loads(data.decode())
        return obj["type"], json.loads(decrypt(obj["payload"]))
    except:
        return None, None

def send_packet(ip, port, type_, payload):
    try:
        with socket.socket() as s:
            s.connect((ip, port))
            s.sendall(encode_packet(type_, payload))
            increment_trust(ip, port)
    except:
        pass

def broadcast(type_, payload):
    for (ip, port) in PEERS.keys():
        send_packet(ip, port, type_, payload)

# === FILE HANDLING ===
def save_file(name, content_b64):
    with open(name, 'wb') as f:
        f.write(base64.b64decode(content_b64))
    print(f"[+] File saved: {name}")

# === CLIENT HANDLER ===
def handle_client(conn, addr):
    try:
        data = conn.recv(BUFFER)
        type_, payload = decode_packet(data)
        if not payload: return
        add_peer(addr[0], addr[1])

        if type_ == "msg":
            print(f"[MSG] {addr[0]}:{addr[1]} -> {payload['text']}")
        elif type_ == "file":
            save_file(payload['name'], payload['content'])
        elif type_ == "sync":
            for peer in payload:
                add_peer(peer[0], peer[1])
    finally:
        conn.close()

# === SERVER LOOP ===
def start_server(host, port):
    srv = socket.socket()
    srv.bind((host, port))
    srv.listen()
    print(f"[+] Node running on {host}:{port}")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

# === STUN NAT DISCOVERY ===
def get_public_ip_port():
    nat_type, external_ip, external_port = stun.get_ip_info(stun_host=STUN_SERVER[0], stun_port=STUN_SERVER[1])
    return external_ip, external_port

# === FLASK HTTP GATEWAY ===
app = Flask(__name__)

@app.route("/peers", methods=["GET"])
def list_peers():
    return jsonify(get_all_peers())

@app.route("/send", methods=["POST"])
def send_to_peer():
    data = request.json
    send_packet(data["ip"], data["port"], "msg", {"text": data["message"]})
    return jsonify({"status": "sent"})

@app.route("/upload", methods=["POST"])
def upload_file():
    file = request.files["file"]
    ip = request.form["ip"]
    port = int(request.form["port"])
    content = base64.b64encode(file.read()).decode()
    send_packet(ip, port, "file", {"name": file.filename, "content": content})
    return jsonify({"status": "uploaded"})

@app.route("/sync", methods=["POST"])
def sync():
    broadcast("sync", get_all_peers())
    return jsonify({"status": "sync started"})

# === CLI INTERFACE ===
def cli_menu():
    while True:
        print("\n== CLI Menu ==")
        print("1. List known peers")
        print("2. Send encrypted message")
        print("3. Upload file to peer")
        print("4. Broadcast message")
        print("5. Sync peers")
        print("6. Show reputation scores")
        print("7. Exit")
        choice = input(">> ")

        if choice == "1":
            peers = get_all_peers()
            for ip, port, trust in peers:
                print(f"- {ip}:{port} | Trust: {trust}")
        elif choice == "2":
            ip = input("Peer IP: ")
            port = int(input("Port: "))
            text = input("Message: ")
            send_packet(ip, port, "msg", {"text": text})
        elif choice == "3":
            ip = input("Peer IP: ")
            port = int(input("Port: "))
            path = input("File path: ")
            if os.path.exists(path):
                with open(path, "rb") as f:
                    b64 = base64.b64encode(f.read()).decode()
                    send_packet(ip, port, "file", {"name": os.path.basename(path), "content": b64})
            else:
                print("[!] File does not exist.")
        elif choice == "4":
            text = input("Broadcast message: ")
            broadcast("msg", {"text": text})
        elif choice == "5":
            broadcast("sync", get_all_peers())
            print("[✓] Peers synced")
        elif choice == "6":
            peers = get_all_peers()
            sorted_peers = sorted(peers, key=lambda x: -x[2])
            for ip, port, trust in sorted_peers:
                print(f"{ip}:{port} -> Trust {trust}")
        elif choice == "7":
            print("[!] Exiting...")
            os._exit(0)
        else:
            print("Invalid choice.")

# === MAIN ENTRY ===
if __name__ == "__main__":
    print("== Encrypted Node Launch ==")
    local_ip = input("Your local IP (0.0.0.0): ").strip() or "0.0.0.0"
    local_port = int(input("Your local port (e.g. 8000): ").strip())

    try:
        pub_ip, pub_port = get_public_ip_port()
        print(f"[STUN] Public IP: {pub_ip}, Port: {pub_port}")
    except Exception as e:
        print(f"[!] STUN failed: {e}")
        pub_ip, pub_port = local_ip, local_port

    add_peer(pub_ip, pub_port)

    threading.Thread(target=start_server, args=(local_ip, local_port), daemon=True).start()

    flask_port = local_port + 1
    print(f"[HTTP] Gateway available at http://localhost:{flask_port}")
    threading.Thread(target=lambda: app.run(port=flask_port), daemon=True).start()

    cli_menu()
