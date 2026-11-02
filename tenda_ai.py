#!/usr/bin/env python3
# TENDA N301 SECURITY AI PRO v1.0
# Defensive local network audit - Termux Android

import os
import re
import json
import socket
import ssl
import subprocess
import ipaddress
import urllib.request
import urllib.error
import concurrent.futures
from datetime import datetime
from getpass import getpass

ROUTER = "192.168.0.1"
REPORT = "tenda_report"
results = {}

# ---------- UI ----------

def clear():
    os.system("clear")

def title():
    print("\033[96m")
    print("=" * 48)
    print("       TENDA N301 SECURITY AI PRO")
    print("            VERSION 1.0")
    print("=" * 48)
    print("\033[0m")

def info(msg):
    print("[*]", msg)

def good(msg):
    print("[+]", msg)

def warn(msg):
    print("[!]", msg)

def pause():
    input("\nTekan ENTER untuk kembali...")

# ---------- NETWORK INFO ----------

def get_network():
    gateway = ROUTER
    interface = None

    try:
        with open("/proc/net/route") as f:
            next(f)
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and parts[1] == "00000000":
                    gateway = socket.inet_ntoa(
                        bytes.fromhex(parts[2])[::-1]
                    )
                    interface = parts[0]
                    break
    except Exception:
        pass

    local_ip = None

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((gateway, 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        pass

    return {
        "router": gateway,
        "local_ip": local_ip,
        "interface": interface
    }

# ---------- PING ----------

def ping_host(host):
    try:
        p = subprocess.run(
            ["ping", "-c", "1", "-W", "1", host],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=3
        )
        if p.returncode == 0:
            match = re.search(r"time[=<]([\d.]+)\s*ms", p.stdout)
            latency = match.group(1) if match else "?"
            return host, latency
    except Exception:
        pass
    return None

def ping_test(host, count=5):
    times = []
    print(f"\nMemeriksa koneksi ke {host}...")
    for i in range(count):
        result = ping_host(host)
        if result:
            times.append(float(result[1]) if result[1] != "?" else 0)
            print(f"  Balasan {i+1}: {result[1]} ms")
        else:
            print(f"  Timeout {i+1}")
    return times

# ---------- ROUTER CHECK ----------

def router_status():
    print("\n=== ROUTER DETECTOR ===")
    net = get_network()
    host = net["router"]

    print("Gateway :", host)
    print("IP HP   :", net["local_ip"] or "Tidak diketahui")
    print("Interface:", net["interface"] or "Tidak diketahui")

    times = ping_test(host, 4)

    if times:
        good("Router merespons ping.")
        results["router_ping"] = times
    else:
        warn("Router tidak merespons ping.")
        warn("Ping mungkin diblokir router.")

    results["network"] = net
    pause()

# ---------- PORT AUDIT ----------

def port_audit():
    print("\n=== ROUTER PORT AUDIT ===")
    host = ROUTER
    ports = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        53: "DNS",
        80: "HTTP Admin",
        443: "HTTPS Admin",
        1900: "UPnP",
        8080: "HTTP Alternate",
        8443: "HTTPS Alternate"
    }

    opened = []

    for port, name in ports.items():
        try:
            s = socket.socket()
            s.settimeout(1.5)
            status = s.connect_ex((host, port))
            s.close()

            if status == 0:
                print(f"[OPEN]   {port} - {name}")
                opened.append({"port": port, "service": name})
            else:
                print(f"[CLOSED] {port} - {name}")
        except Exception as e:
            print(f"[ERROR] {port}: {e}")

    results["open_ports"] = opened

    if any(x["port"] in (21, 23) for x in opened):
        warn("FTP/Telnet terbuka. Periksa apakah layanan ini diperlukan.")
    else:
        good("Tidak ditemukan FTP/Telnet pada port yang diperiksa.")

    pause()

# ---------- WEB ADMIN CHECK ----------

def web_check():
    print("\n=== WEB ADMIN CHECK ===")
    urls = [
        f"http://{ROUTER}/",
        f"https://{ROUTER}/"
    ]

    found = []

    for url in urls:
        print("\nMemeriksa:", url)
        try:
            context = ssl._create_unverified_context()
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=context)
            )
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Tenda-Security-Audit/1.0"}
            )
            with opener.open(req, timeout=4) as response:
                data = response.read(4096).decode(
                    "utf-8", errors="ignore"
                )
                server = response.headers.get("Server", "Tidak diketahui")
                print("HTTP status:", response.status)
                print("Server:", server)
                print("Content-Type:",
                      response.headers.get("Content-Type", "?"))
                found.append({
                    "url": url,
                    "status": response.status,
                    "server": server
                })
                if "login" in data.lower() or "password" in data.lower():
                    good("Kemungkinan halaman login terdeteksi.")
        except urllib.error.HTTPError as e:
            print("HTTP status:", e.code)
        except Exception as e:
            print("Tidak dapat diakses:", str(e)[:100])

    results["web_admin"] = found
    pause()

# ---------- DEVICE SCANNER ----------

def device_scan():
    print("\n=== LOCAL NETWORK SCANNER ===")
    net = get_network()
    local_ip = net["local_ip"]

    if not local_ip:
        warn("IP HP tidak berhasil dideteksi.")
        pause()
        return

    try:
        network = ipaddress.ip_network(
            local_ip + "/24", strict=False
        )
    except Exception:
        warn("Subnet tidak dapat ditentukan.")
        pause()
        return

    print("Jaringan:", network)
    print("Memindai perangkat yang merespons ping...")
    print("Mohon tunggu beberapa saat.\n")

    hosts = [
        str(ip) for ip in network.hosts()
        if str(ip) != local_ip
    ]

    active = []

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=32
    ) as executor:
        for item in executor.map(ping_host, hosts):
            if item:
                active.append({
                    "ip": item[0],
                    "latency_ms": item[1]
                })
                print(
                    "[ONLINE] {} | {} ms".format(
                        item[0], item[1]
                    )
                )

    print("\nTotal perangkat yang merespons:", len(active))
    print("Catatan: perangkat yang memblokir ping tidak akan terdeteksi.")

    results["devices"] = active
    pause()

# ---------- CONNECTION MONITOR ----------

def stability_test():
    print("\n=== CONNECTION STABILITY ===")
    target = input(
        "Target IP [192.168.0.1]: "
    ).strip() or ROUTER

    try:
        ipaddress.ip_address(target)
    except ValueError:
        warn("Masukkan alamat IP yang valid.")
        pause()
        return

    times = ping_test(target, 10)

    if times:
        avg = sum(times) / len(times)
        print("\nPaket berhasil:", len(times), "/ 10")
        print("Rata-rata latency: {:.2f} ms".format(avg))

        if avg < 30:
            good("Latency rendah.")
        elif avg < 100:
            warn("Latency sedang.")
        else:
            warn("Latency tinggi.")

        results["stability"] = {
            "target": target,
            "success": len(times),
            "average_ms": round(avg, 2)
        }
    else:
        warn("Tidak ada balasan ping.")

    pause()

# ---------- PASSWORD ANALYZER ----------

def password_check():
    print("\n=== WIFI PASSWORD ANALYZER ===")
    print("Password hanya diperiksa secara lokal.")
    password = getpass("Masukkan password WiFi: ")

    score = 0
    tips = []

    if len(password) >= 12:
        score += 2
    else:
        tips.append("Gunakan minimal 12 karakter.")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        tips.append("Tambahkan huruf besar.")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        tips.append("Tambahkan huruf kecil.")

    if re.search(r"[0-9]", password):
        score += 1
    else:
        tips.append("Tambahkan angka.")

    if re.search(r"[^A-Za-z0-9]", password):
        score += 1
    else:
        tips.append("Tambahkan simbol.")

    if score >= 5:
        level = "KUAT"
    elif score >= 3:
        level = "SEDANG"
    else:
        level = "LEMAH"

    print("\nNilai:", score, "/ 6")
    print("Kategori:", level)

    for tip in tips:
        print(" -", tip)

    results["password_audit"] = {
        "score": score,
        "level": level
    }

    del password
    pause()

# ---------- SECURITY ADVISOR ----------

def advisor():
    print("\n=== SECURITY ADVISOR ===")

    net = get_network()
    print("\nREKOMENDASI KEAMANAN TENDA N301:")

    recommendations = [
        "Gunakan WPA2-PSK dengan AES jika tersedia.",
        "Gunakan password WiFi unik minimal 12-16 karakter.",
        "Nonaktifkan WPS jika tidak diperlukan.",
        "Ganti password administrator router.",
        "Nonaktifkan remote management dari internet.",
        "Periksa daftar perangkat yang terhubung.",
        "Perbarui firmware hanya dari situs resmi TENDA.",
        "Matikan UPnP jika tidak dibutuhkan.",
        "Gunakan jaringan tamu jika tersedia.",
        "Jangan membagikan password admin router."
    ]

    for i, item in enumerate(recommendations, 1):
        print(f"{i}. {item}")

    opened = results.get("open_ports", [])
    if any(p["port"] == 23 for p in opened):
        warn("Telnet terbuka: evaluasi dan nonaktifkan jika tidak diperlukan.")

    print("\nGateway terdeteksi:", net["router"])
    pause()

# ---------- REPORT ----------

def save_report():
    print("\n=== SAVE SECURITY REPORT ===")
    os.makedirs(REPORT, exist_ok=True)

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(
        REPORT, f"tenda_{stamp}.json"
    )

    report = {
        "tool": "TENDA N301 SECURITY AI PRO",
        "date": datetime.now().isoformat(),
        "target": ROUTER,
        "results": results
    }

    try:
        with open(filename, "w") as f:
            json.dump(report, f, indent=4)

        good("Laporan tersimpan:")
        print(filename)
    except Exception as e:
        warn(str(e))

    pause()

# ---------- MAIN MENU ----------

def main():
    while True:
        clear()
        title()

        print("Target router:", ROUTER)
        print()
        print("[1] Router Detector")
        print("[2] Local Network Scanner")
        print("[3] Router Port Audit")
        print("[4] Web Admin Checker")
        print("[5] Connection Stability Test")
        print("[6] WiFi Password Analyzer")
        print("[7] AI Security Advisor")
        print("[8] Save Security Report")
        print("[9] Exit")

        choice = input("\nPilih menu: ").strip()

        if choice == "1":
            router_status()
        elif choice == "2":
            device_scan()
        elif choice == "3":
            port_audit()
        elif choice == "4":
            web_check()
        elif choice == "5":
            stability_test()
        elif choice == "6":
            password_check()
        elif choice == "7":
            advisor()
        elif choice == "8":
            save_report()
        elif choice == "9":
            print("Terima kasih!")
            break
        else:
            warn("Pilihan tidak valid.")
            pause()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nProgram dihentikan.")

