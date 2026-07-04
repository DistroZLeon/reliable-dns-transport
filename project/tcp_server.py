import socket
import os
import threading

def handle_client(conn, addr):
    try:
        header = b""
        while not header.endswith(b"\n"):
            chunk = conn.recv(1)
            if not chunk: break
            header += chunk
        
        parts = header.decode('utf-8', errors='ignore').strip().split('|')
        action = parts[0]
        
        if action == "UPL":
            filename, filesize = parts[1], int(parts[2])
            received = 0
            with open(filename, "wb") as f:
                while received < filesize:
                    data = conn.recv(min(4096, filesize - received))
                    if not data: break
                    f.write(data)
                    received += len(data)
            print(f"+ TCP: Received {filename} ({received} bytes)")
            
            conn.sendall(b"ACK\n")
            
        elif action == "DWN":
            filename = parts[1]
            if os.path.exists(filename):
                filesize = os.path.getsize(filename)
                conn.sendall(f"OK|{filesize}\n".encode('utf-8'))
                with open(filename, "rb") as f:
                    conn.sendfile(f)
                print(f"+ TCP: Sent {filename} ({filesize} bytes)")
            else:
                conn.sendall(b"ERR|File not found\n")
                
    except Exception as e:
        if "utf-8" not in str(e) and "invalid literal" not in str(e):
            print(f"- TCP Error with {addr}: {e}")
    finally:
        conn.close()

def start_tcp_server(host='0.0.0.0', port=9000):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"* TCP Benchmark Server listening on {host}:{port}...")

    while True:
        conn, addr = server_socket.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()

if __name__ == "__main__":
    start_tcp_server()
