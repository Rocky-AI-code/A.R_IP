# 🔐 Module Auto-Installer
try:
    import requests, socket, threading
    from datetime import datetime
    from colorama import Fore, Style, init
except ModuleNotFoundError:
    import os
    import sys
    print("[!] Installing missing modules...")
    os.system(f"{sys.executable} -m pip install requests colorama")
    import requests, socket, threading
    from datetime import datetime
    from colorama import Fore, Style, init

init(autoreset=True)

def banner():
    print(Fore.CYAN + Style.BRIGHT + r"""
██████╗ ██████╗ ██████╗  █████╗ ██████╗ █████§
╚══██╔╝██╔═══██╗██╔══██╗██╔══██╗██╔══██╗██╔══╝
   ██╔╝ ██║   ██║██████╔╝███████║██████╔╝█████╗
  ██╔╝  ██║   ██║██╔═══╝ ██╔══██║██╔═══╝ ██╔══╝
 ██████╗╚██████╔╝██║     ██║  ██║██║     █████§
 ╚═════╝ ╚═════╝ ╚═╝     ╚═╝  ╚═╝╚═╝     ╚════╝
   ➤ Arbab§ IP Intelligence Tool | Multi-threaded
────────────────────────────────────────────
""")

def get_ip_info(ip):
    print(Fore.YELLOW + "[+] Fetching IP info...\n")

    info = {}

    try:
        res1 = requests.get(f"http://ip-api.com/json/{ip}").json()
        info['country'] = res1.get("country")
        info['region'] = res1.get("regionName")
        info['city'] = res1.get("city")
        info['zip'] = res1.get("zip")
        info['lat'] = res1.get("lat")
        info['lon'] = res1.get("lon")
        info['isp'] = res1.get("isp")
        info['org'] = res1.get("org")
        info['asn'] = res1.get("as")
    except:
        print(Fore.RED + "[!] Error fetching geo data.")

    # Reverse DNS Lookup
    try:
        host = socket.gethostbyaddr(ip)[0]
        info['reverse_dns'] = host
    except:
        info['reverse_dns'] = "N/A"

    # IP Reputation (simple proxy/vpn check)
    try:
        vpn_check = requests.get(f"https://ipwho.is/{ip}").json()
        info['proxy'] = vpn_check.get("proxy")
        info['vpn'] = vpn_check.get("vpn")
    except:
        info['proxy'] = info['vpn'] = False

    return info

open_ports = []
def scan_port(ip, port):
    try:
        s = socket.socket()
        s.settimeout(0.5)
        s.connect((ip, port))
        open_ports.append(port)
        s.close()
    except:
        pass

def scan_ports(ip):
    print(Fore.YELLOW + "[+] Scanning common ports (multi-threaded)...")
    threads = []
    for port in [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 8080]:
        t = threading.Thread(target=scan_port, args=(ip, port))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

def save_report(ip, info):
    filename = f"arbab_{ip}_{datetime.now().strftime('%Y-%m-%d_%H-%M')}.txt"
    with open(filename, "w") as f:
        f.write(f"Arbab§ IP Report for: {ip}\n")
        f.write("-" * 40 + "\n")
        for key, val in info.items():
            f.write(f"{key.capitalize():15}: {val}\n")
        f.write(f"Open Ports        : {', '.join(map(str, open_ports)) if open_ports else 'None'}\n")
    print(Fore.GREEN + f"\n📝 Report saved: {filename}")

def main():
    banner()
    ip = input(Fore.CYAN + "[?] Enter IP to investigate: ").strip()
    info = get_ip_info(ip)

    print(Fore.GREEN + f"\n🌍 Country        : {info['country']}")
    print(f"🏙️  City           : {info['city']} — Zip: {info['zip']}")
    print(f"🌐 ISP            : {info['isp']} | ASN: {info['asn']}")
    print(f"📡 Reverse DNS    : {info['reverse_dns']}")
    print(f"🛡️  Proxy/VPN      : {'✅ Detected' if info['proxy'] or info['vpn'] else '❌ Clean IP'}")

    scan_ports(ip)
    print(Fore.CYAN + f"\n[+] Open Ports: {', '.join(map(str, open_ports)) if open_ports else 'None'}")

    save_report(ip, info)
    input(Fore.YELLOW + "\nPress Enter to exit...")

if __name__ == "__main__":
    main()