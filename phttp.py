import socket
import threading
import base64
import os
import sys
import time

# --- Configuration ---
PEERS = set()
FILES = {}
DB = {}
PORT = None
RUNNING = True

def encrypt(data):
    return base64.b64encode(data.encode()).decode()

def decrypt(data):
    return base64.b64decode(data.encode()).decode()

def save_peer(ip, port):
    PEERS.add((ip, port))
    with open("peers.db", "w") as f:
        for ip, port in PEERS:
            f.write(f"{ip}:{port}\n")

def load_peers():
    if os.path.exists("peers.db"):
        with open("peers.db", "r") as f:
            for line in f:
                ip, port = line.strip().split(":")
                PEERS.add((ip, int(port)))

def send_to_peer(ip, port, msg):
    try:
        s = socket.socket()
        s.connect((ip, port))
        s.send(msg.encode())
        s.close()
    except:
        pass

def broadcast(msg):
    for ip, port in list(PEERS):
        send_to_peer(ip, port, msg)

def handle_connection(conn, addr):
    try:
        data = conn.recv(65536).decode()
        if data.startswith("PEER:"):
            ip, port = data[5:].split(":")
            save_peer(ip, int(port))
            conn.send("PEER_OK".encode())
        elif data.startswith("MSG:"):
            msg = data[4:]
            print(f"[MSG from {addr}]: {msg}")
        elif data.startswith("FILE:"):
            fname, content = data[5:].split("::", 1)
            FILES[fname] = decrypt(content)
            print(f"[RECEIVED FILE]: {fname}")
        elif data.startswith("DB:"):
            key, val = data[3:].split("::", 1)
            DB[key] = val
            print(f"[SYNCED DB]: {key} -> {val}")
        elif data == "LIST":
            conn.send("FILES:\n".encode() + "\n".join(FILES.keys()).encode())
        elif data.startswith("GET:"):
            fname = data[4:]
            if fname in FILES:
                conn.send(FILES[fname].encode())
            else:
                conn.send("FILE NOT FOUND".encode())
    except:
        pass
    finally:
        conn.close()

def server():
    s = socket.socket()
    s.bind(("0.0.0.0", PORT))
    s.listen(10)
    print(f"[SERVER] Listening on port {PORT}")
    while RUNNING:
        try:
            conn, addr = s.accept()
            threading.Thread(target=handle_connection, args=(conn, addr), daemon=True).start()
        except:
            continue

def cli():
    print("\n--- P2P Node Menu ---")
    print("1. Connect to peer")
    print("2. Send message")
    print("3. Broadcast message")
    print("4. Share file")
    print("5. List files")
    print("6. Get file")
    print("7. Sync DB")
    print("8. View DB")
    print("9. HTTP Gateway")
    print("0. Exit")

def start_http_gateway():
    def gateway():
        gs = socket.socket()
        gs.bind(("0.0.0.0", PORT + 1000))
        gs.listen(5)
        print(f"[HTTP Gateway] Listening on http://localhost:{PORT + 1000}")
        while True:
            conn, addr = gs.accept()
            req = conn.recv(1024).decode()
            response = "HTTP/1.1 200 OK\nContent-Type: text/html\n\n"
            response += "<html><body><h1>Decentralized Node</h1><ul>"
            for f in FILES:
                response += f"<li>{f}</li>"
            response += "</ul></body></html>"
            conn.sendall(response.encode())
            conn.close()
    threading.Thread(target=gateway, daemon=True).start()

def main():
    global PORT, RUNNING
    try:
        PORT = int(input("Enter your node port (e.g., 3000): ").strip())
    except:
        print("Invalid port.")
        return

    load_peers()
    threading.Thread(target=server, daemon=True).start()
    start_http_gateway()

    while True:
        cli()
        choice = input("Select: ").strip()
        if choice == "1":
            ip = input("Peer IP: ").strip()
            port = int(input("Peer Port: ").strip())
            save_peer(ip, port)
            send_to_peer(ip, port, f"PEER:127.0.0.1:{PORT}")
        elif choice == "2":
            ip = input("Peer IP: ").strip()
            port = int(input("Peer Port: ").strip())
            msg = input("Message: ").strip()
            send_to_peer(ip, port, f"MSG:{msg}")
        elif choice == "3":
            msg = input("Broadcast Message: ").strip()
            broadcast(f"MSG:{msg}")
        elif choice == "4":
            fname = input("Filename: ").strip()
            if os.path.exists(fname):
                with open(fname, "r") as f:
                    content = f.read()
                    FILES[fname] = content
                    encoded = encrypt(content)
                    broadcast(f"FILE:{fname}::{encoded}")
            else:
                print("File not found.")
        elif choice == "5":
            print("--- Files ---")
            for f in FILES:
                print(f)
        elif choice == "6":
            fname = input("Filename to fetch: ").strip()
            ip = input("Peer IP: ").strip()
            port = int(input("Peer Port: ").strip())
            try:
                s = socket.socket()
                s.connect((ip, port))
                s.send(f"GET:{fname}".encode())
                data = s.recv(65536).decode()
                print("[Received]:", data)
                s.close()
            except:
                print("Error getting file.")
        elif choice == "7":
            key = input("Key: ").strip()
            val = input("Value: ").strip()
            DB[key] = val
            broadcast(f"DB:{key}::{val}")
        elif choice == "8":
            print("--- DB ---")
            for k in DB:
                print(f"{k} = {DB[k]}")
        elif choice == "9":
            print("HTTP Gateway is already running at http://localhost:", PORT + 1000)
        elif choice == "0":
            print("Shutting down.")
            RUNNING = False
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
