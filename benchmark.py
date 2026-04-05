import os
import time
import socket
import matplotlib.pyplot as plt
import numpy as np
from client import Client
from dotenv import load_dotenv

load_dotenv()
SERVER_IP = os.getenv('IPV4')
TCP_PORT = 9000
TEST_FILES = {
    "5KB": 5* 1024,
    "10KB": 10* 1024,
    "25KB": 25* 1024, 
    "50KB": 50* 1024, 
    "100KB": 100* 1024,
    "175KB": 175 * 1024,
    "250KB": 250* 1024,
    "500KB": 500* 1024,
    "750KB": 750 * 1024,
    "1MB": 1000* 1024
}

def generate_dummy_file(filename, size_bytes):
    print(f"\n* Generating {filename}...")
    with open(filename, "wb") as f:
        f.write(os.urandom(size_bytes))

def benchmark_tcp_upl(filepath, server_ip, port):
    filename, filesize = os.path.basename(filepath), os.path.getsize(filepath)
    start_time = time.time()
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((server_ip, port))
    sock.sendall(f"UPL|{filename}|{filesize}\n".encode('utf-8'))
    
    with open(filepath, "rb") as f:
        sock.sendfile(f)
    sock.recv(4) 
    sock.close()
    
    return time.time() - start_time

def benchmark_tcp_dwn(filename, server_ip, port):
    start_time = time.time()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((server_ip, port))
    sock.sendall(f"DWN|{filename}\n".encode('utf-8'))
    
    header = b""
    while not header.endswith(b"\n"):
        header += sock.recv(1)
        
    parts = header.decode('utf-8').strip().split('|')
    if parts[0] == "OK":
        filesize, received = int(parts[1]), 0
        with open(f"dl_tcp_{filename}", "wb") as f:
            while received < filesize:
                data = sock.recv(min(4096, filesize - received))
                if not data: break
                f.write(data)
                received += len(data)
    sock.close()
    if os.path.exists(f"dl_tcp_{filename}"): os.remove(f"dl_tcp_{filename}")
    return time.time() - start_time

def benchmark_dns_upl(filepath):
    client = Client()
    if not hasattr(client, 'retries_count'):
        client.retries_count = 0
        
    if not client.handshake(): return None, 0
    start = time.time()
    if not client.upload(filepath): return None, client.retries_count
    
    return time.time() - start, client.retries_count

def benchmark_dns_dwn(filename):
    client = Client()
    if not hasattr(client, 'retries_count'):
        client.retries_count = 0
        
    if not client.handshake(): return None, 0
    start = time.time()
    if not client.download(filename): return None, client.retries_count
    
    for f in os.listdir(client.upload_dir):
        if f.startswith(filename.split('.')[0]) and "dl_dns" not in f:
            os.remove(os.path.join(client.upload_dir, f))
            
    return time.time() - start, client.retries_count

# --- PLOTTING ---
def generate_graphs(labels, tcp_u, tcp_d, dns_u, dns_d, retries_u, retries_d):
    print("\n* Generating Matplotlib graphs...")
    sizes_kb = [TEST_FILES[l] / 1024 for l in labels]
    
    tp_tcp_u = [sizes_kb[i] / tcp_u[i] for i in range(len(labels))]
    tp_tcp_d = [sizes_kb[i] / tcp_d[i] for i in range(len(labels))]
    tp_dns_u = [sizes_kb[i] / dns_u[i] for i in range(len(labels))]
    tp_dns_d = [sizes_kb[i] / dns_d[i] for i in range(len(labels))]

    x = np.arange(len(labels))
    width = 0.2

    fig = plt.figure(figsize=(16, 12))
    
    ax1 = plt.subplot2grid((2, 4), (0, 0), colspan=2)
    ax2 = plt.subplot2grid((2, 4), (0, 2), colspan=2)
    ax3 = plt.subplot2grid((2, 4), (1, 1), colspan=2)

    # Graph 1: Latency
    ax1.bar(x - 1.5*width, tcp_u, width, label='TCP Upload', color='#1f77b4')
    ax1.bar(x - 0.5*width, tcp_d, width, label='TCP Download', color='#a6cee3')
    ax1.bar(x + 0.5*width, dns_u, width, label='DNS Upload', color='#d62728')
    ax1.bar(x + 1.5*width, dns_d, width, label='DNS Download', color='#fb9a99')
    ax1.set_ylabel('Time in Seconds')
    ax1.set_title('Transfer Latency')
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, rotation=45, ha='right')
    ax1.set_yscale('log')
    ax1.legend()
    ax1.grid(True, axis='y', linestyle='--', alpha=0.7)

    # Graph 2: Throughput
    ax2.plot(labels, tp_tcp_u, marker='o', label='TCP Upload', color='#1f77b4', linewidth=2)
    ax2.plot(labels, tp_tcp_d, marker='o', linestyle='--', label='TCP Download', color='#a6cee3', linewidth=2)
    ax2.plot(labels, tp_dns_u, marker='s', label='DNS Upload', color='#d62728', linewidth=2)
    ax2.plot(labels, tp_dns_d, marker='s', linestyle='--', label='DNS Download', color='#fb9a99', linewidth=2)
    ax2.set_ylabel('Throughput KB/s')
    ax2.set_title('Effective Data Rate')
    ax2.set_xticks(x)
    ax2.set_xticklabels(labels, rotation=45, ha='right')
    ax2.set_yscale('log')
    ax2.legend()
    ax2.grid(True, axis='both', linestyle='--', alpha=0.7)

    # Graph 3: Retries
    ax3.plot(labels, retries_u, marker='^', label='DNS Upload Retries', color='#d62728', linewidth=2)
    ax3.plot(labels, retries_d, marker='v', linestyle='--', label='DNS Download Retries', color='#fb9a99', linewidth=2)
    ax3.plot(labels, [0]*len(labels), marker='x', label='TCP Baseline', color='#1f77b4', alpha=0.5)
    ax3.set_ylabel('Total Retries Triggered')
    ax3.set_title('Packet Loss & Rate Limiting Resistance')
    ax3.set_xticks(x)
    ax3.set_xticklabels(labels, rotation=45, ha='right')
    ax3.legend()
    ax3.grid(True, axis='both', linestyle='--', alpha=0.7)

    plt.tight_layout()
    plt.savefig('benchmark_results.png', dpi=300) 
    print("+ Graphs saved to 'benchmark_results.png'!")

if __name__ == "__main__":
    labels = list(TEST_FILES.keys())
    tcp_upl, tcp_dwn = [], []
    dns_upl, dns_dwn = [], []
    dns_retries_u, dns_retries_d = [], []

    for label, size in TEST_FILES.items():
        filename = f"bench_{label}.dat"
        generate_dummy_file(filename, size)

        tcp_upl.append(benchmark_tcp_upl(filename, SERVER_IP, TCP_PORT))
        tcp_dwn.append(benchmark_tcp_dwn(filename, SERVER_IP, TCP_PORT))
        
        t_up, r_up = benchmark_dns_upl(filename)
        t_dwn, r_dwn = benchmark_dns_dwn(filename)
        
        dns_upl.append(t_up)
        dns_retries_u.append(r_up)
        
        dns_dwn.append(t_dwn)
        dns_retries_d.append(r_dwn)
        
        os.remove(filename)

    generate_graphs(labels, tcp_upl, tcp_dwn, dns_upl, dns_dwn, dns_retries_u, dns_retries_d)