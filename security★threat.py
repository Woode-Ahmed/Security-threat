import socket
import requests
from scapy.all import ARP, Ether, srp

a12 = '\x1b[38;5;220m'  # ذهبي
a13 = '\x1b[38;5;7m'  # فضي
a14 = '\x1b[38;5;153m'  # أزرق فاتح
a15 = '\x1b[38;5;18m'  # أزرق داكن
Z1 = '\033[2;31m'  # احمر ثاني
F = '\033[2;32m'  # اخضر
A = '\033[2;34m'  # ازرق
C = '\033[2;35m'  # وردي

print('''\033[01;32m
    
    </> WOODE ->@c249c
    
    </>NO BRAK ->@NO_BRAK
    
    </>No breaking, my friend

    </>We hope for Sudan's return
    
    ''')

print(a12 + ' ═════════════════════════════════  ')

def scan_ports(target_ip):
    print(f"Scanning ports on {target_ip}...")
    open_ports = []
    for port in range(1, 1025):  
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    print(f"Open ports on {target_ip}: {open_ports}")

def sniff_network(interface):
    print(f"Scanning network on interface {interface}...")
    arp_request = ARP(pdst="192.168.1.0/24")  
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered, _ = srp(arp_request_broadcast, timeout=2, verbose=0)
    devices = []
    for sent, received in answered:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    print("Devices found:")
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}")

def check_website_status(url):
    print(f"Checking status of {url}...")
    try:
        response = requests.get(url)
        print(f"Website {url} is reachable. Status code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Error checking website: {e}")

def domain_to_ip(domain):
    print(f"Converting domain {domain} to IP address...")
    try:
        ip_address = socket.gethostbyname(domain)
        print(f"The IP address of {domain} is: {ip_address}")
    except socket.gaierror:
        print(f"Error: Unable to resolve {domain} to an IP address.")

def extract_subdomains(domain):
    print(f"Extracting subdomains for {domain}...")
    
    subdomains = ["www", "mail", "ftp", "blog", "shop", "api"]
    found_subdomains = []

    for subdomain in subdomains:
        url = f"http://{subdomain}.{domain}"
        try:
            response = requests.get(url, timeout=2)
            if response.status_code == 200:
                print(f"Found subdomain: {url}")
                found_subdomains.append(url)
        except requests.exceptions.RequestException:
            pass  

   
    file_name = "woode.txt"
    with open(file_name, "w") as file:
        for sub in found_subdomains:
            file.write(sub + "\n")

    print(f"Subdomains saved to file: {file_name}")

if __name__ == "__main__":
    print(C+"         »Select an option:")
    print(a12 + ' ═════════════════════════════════  ')
    print(a14+"1. 𝙊𝙥𝙚𝙣 𝙋𝙤𝙧𝙩 𝘿𝙚𝙩𝙚𝙘𝙩𝙞𝙤𝙣")
    print(a15+"2. 𝗦𝗻𝗶𝗳𝗳 𝗻𝗲𝘁𝘄𝗼𝗿𝗸 𝗱𝗲𝘃𝗶𝗰𝗲𝘀 𝗼𝗻 𝘆𝗼𝘂𝗿 𝗶𝗻𝘁𝗲𝗿𝗳𝗮𝗰𝗲")
    print(a14+"3. 𝗖𝗵𝗲𝗰𝗸 𝘁𝗵𝗲 𝘀𝘁𝗮𝘁𝘂𝘀 𝗼𝗳 𝗮 𝘄𝗲𝗯𝘀𝗶𝘁𝗲")
    print(a15+"4. 𝗖𝗼𝗻𝘃𝗲𝗿𝘁 𝗮 𝗱𝗼𝗺𝗮𝗶𝗻 𝗻𝗮𝗺𝗲 𝘁𝗼 𝗮𝗻 𝗜𝗣 𝗮𝗱𝗱𝗿𝗲𝘀𝘀")
    print(a14+"5. 𝗦𝘂𝗯𝗱𝗼𝗺𝗮𝗶𝗻𝘀 𝗼𝗳 𝗮 𝗗𝗼𝗺𝗮𝗶𝗻")
    print(a12 + ' ═════════════════════════════════  ')
    choice = input(C+"𝐄𝐍𝐓𝐄𝐑 𝐂𝐇𝐎𝐈𝐂𝐄»» ")
    
    if choice == "1":
        target_ip = input("Enter the target IP: ")
        scan_ports(target_ip)
    elif choice == "2":
        interface = input("Enter your network interface (e.g., eth0, wlan0): ")
        sniff_network(interface)
    elif choice == "3":
        url = input("Enter the website URL: ")
        check_website_status(url)
    elif choice == "4":
        domain = input("Enter the domain name (e.g., google.com): ")
        domain_to_ip(domain)
    elif choice == "5":
        domain = input("Enter the domain name (e.g., example.com): ")
        extract_subdomains(domain)
    else:
        print("Invalid choice!")