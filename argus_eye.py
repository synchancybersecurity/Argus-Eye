#!/usr/bin/env python3
import socket, threading, subprocess, sys, re, time, base64
from concurrent.futures import ThreadPoolExecutor, as_completed

CAMERA_PORTS = {
    80:"HTTP",81:"HTTP-Alt",82:"HTTP-Alt2",88:"Webcam",443:"HTTPS",
    554:"RTSP",8000:"Hikvision",8080:"HTTP-Proxy",8443:"HTTPS-Alt",
    8554:"RTSP-Alt",8888:"Generic-Cam",9000:"WebcamXP",
    37777:"Dahua",37778:"Dahua2",5150:"IPCam",5160:"IPCam2",
    21:"FTP",23:"Telnet",8001:"DVR/NVR",10554:"RTSP-Alt2",2020:"ONVIF",
}

CAMERA_FINGERPRINTS = [
    b"Hikvision",b"Dahua",b"Netcam",b"webcam",b"IPCAM",b"Camera",b"camera",
    b"Live View",b"live view",b"DVR",b"NVR",b"XVR",b"Network Video",
    b"Motion-JPEG",b"mjpg",b"MJPG",b"Server: Boa",b"Server: lighttpd",
    b"<title>IP Camera</title>",b"<title>Network Camera</title>",
    b"<title>Webcam</title>",b'Basic realm="camera"',b'Basic realm="DVR"',
    b"<title>NETSurveillance</title>",b"ONVIF",b"onvif",
]

DEFAULT_CREDS = {
    "Hikvision":[("admin","12345"),("admin","admin"),("admin","123456"),("admin","hik12345")],
    "Dahua":[("admin","admin"),("admin","123456"),("admin","12345"),("888888","888888"),("666666","666666"),("admin","tlJwpbo6")],
    "Amcrest":[("admin","admin"),("admin","password")],
    "Reolink":[("admin",""),("admin","admin")],
    "Axis":[("root","pass"),("root","root")],
    "Foscam":[("admin",""),("admin","admin")],
    "Generic":[("admin","admin"),("admin","12345"),("admin","123456"),("admin","password"),("admin",""),("root","root"),("root","admin"),("user","user"),("guest","guest")],
}

SNAPSHOT_URLS = {
    "Hikvision":["/ISAPI/Streaming/channels/101/picture","/ISAPI/Streaming/channels/102/picture","/Streaming/channels/1/picture","/cgi-bin/snapshot.cgi"],
    "Dahua":["/cgi-bin/snapshot.cgi","/cgi-bin/net_jpeg.cgi?ch=0","/cgi-bin/net_jpeg.cgi?ch=1","/onvif-http/snapshot?Profile_1"],
    "Generic":["/snapshot.jpg","/snapshot.cgi","/image.jpg","/tmpfs/auto.jpg","/cgi-bin/snapshot.cgi","/onvif-http/snapshot","/video/mjpg.cgi","/mjpg/video.mjpg","/cgi-bin/video.jpg","/api/camera/snapshot","/snap.jpg"],
}

RTSP_PATHS = ["/live/ch00_0","/live/ch01_0","/videoMain","/videoSub","/onvif1","/cam/realmonitor?channel=1&subtype=0","/Streaming/Channels/101","/stream1","/stream2","/live.sdp","/mpeg4/media.amp","/ch01_0","/0","/1","/onvif/profile1"]

TIMEOUT = 3.0
MAX_WORKERS = 30
results_lock = threading.Lock()
found_devices = []

def get_local_subnet():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8",80))
        local_ip = s.getsockname()[0]
        s.close()
        p = local_ip.split(".")
        return f"{p[0]}.{p[1]}.{p[2]}.", local_ip
    except:
        return None,None

def get_arp_entries():
    devices = {}
    try:
        out = subprocess.run(["cat","/proc/net/arp"], capture_output=True, text=True)
        for line in out.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 4:
                ip, mac = parts[0], parts[3]
                if re.match(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", mac):
                    devices[ip] = mac
    except:
        pass
    try:
        out = subprocess.run(["ip","neigh"], capture_output=True, text=True)
        for line in out.stdout.splitlines():
            m = re.search(r"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*?lladdr ([0-9a-f:]+)", line)
            if m:
                devices[m.group(1)] = m.group(2)
    except:
        pass
    return devices

def http_request(ip, port, path, auth=None, timeout=TIMEOUT):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        proto = "HTTPS" if port in (443,8443) else "HTTP"
        headers = [f"GET {path} {proto}/1.1", f"Host: {ip}:{port}", "User-Agent: Mozilla/5.0", "Accept: text/html,image/*,*/*", "Connection: close"]
        if auth:
            headers.append(f"Authorization: Basic {base64.b64encode(f'{auth[0]}:{auth[1]}'.encode()).decode()}")
        req = "\r\n".join(headers) + "\r\n\r\n"
        s.send(req.encode())
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        s.close()
        return data
    except:
        return None

def grab_banner(ip, port):
    banners = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((ip, port))
        if port in (80,81,82,88,8080,8000,443,8443,8888,2020):
            req = f"GET / HTTP/1.1\r\nHost: {ip}:{port}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
            s.send(req.encode())
            data = s.recv(4096)
            if data:
                t = re.search(b"<title>(.*?)</title>", data, re.I)
                if t:
                    banners.append(f"Title: {t.group(1).decode('utf-8','ignore')[:60]}")
                srv = re.search(b"Server: ([^\r\n]+)", data, re.I)
                if srv:
                    banners.append(f"Server: {srv.group(1).decode('utf-8','ignore')[:40]}")
                auth = re.search(b'realm="([^"]+)"', data, re.I)
                if auth:
                    banners.append(f"Auth: {auth.group(1).decode('utf-8','ignore')}")
                for fp in CAMERA_FINGERPRINTS:
                    if fp in data:
                        banners.append(f"Fingerprint: {fp.decode('utf-8','ignore')}")
                        break
        else:
            s.send(b"\r\n")
            data = s.recv(1024)
            if data:
                txt = data.decode("utf-8","ignore").strip()[:60]
                if txt:
                    banners.append(f"Banner: {txt}")
        s.close()
    except:
        pass
    return banners

def check_rtsp(ip, port=554):
    rtsp_info = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((ip, port))
        req = f"DESCRIBE rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: ArgusEye\r\nAccept: application/sdp\r\n\r\n"
        s.send(req.encode())
        data = s.recv(1024)
        if data and b"RTSP/1.0" in data:
            code = data.split(b" ")[1].decode() if len(data.split(b" ")) > 1 else "???"
            rtsp_info.append(f"RTSP response: {code}")
            if b"401" in data or b"403" in data:
                rtsp_info.append("Auth required (likely camera)")
        s.close()
    except:
        pass
    return rtsp_info

def scan_host(ip, mac_map):
    open_ports = []
    for port, svc in CAMERA_PORTS.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(TIMEOUT)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append((port, svc))
            s.close()
        except:
            pass
    if not open_ports:
        return
    banners = []
    for port, _ in open_ports:
        b = grab_banner(ip, port)
        if b:
            banners.extend(b)
    rtsp_data = check_rtsp(ip) if any(p[0] == 554 for p in open_ports) else []
    score = 0
    indicators = []
    for port, svc in open_ports:
        if port in (554,8554,10554):
            score += 3; indicators.append("RTSP port")
        if port in (37777,37778,8000,8001):
            score += 3; indicators.append("DVR/NVR port")
        if port == 2020:
            score += 2; indicators.append("ONVIF port")
        if port in (80,8080,81,82,88,8888,443,8443):
            score += 1
    for b in banners:
        bl = b.lower()
        for fp in CAMERA_FINGERPRINTS:
            if fp.decode("utf-8","ignore").lower() in bl:
                score += 2; indicators.append(f"Banner: {b[:35]}"); break
    for r in rtsp_data:
        if "Auth required" in r:
            score += 2; indicators.append("RTSP auth wall")
    mac = mac_map.get(ip, "Unknown")
    oui = []
    if mac != "Unknown":
        mac_pre = mac[:8].upper()
        cam_ouis = ["00:12:3F","4C:11:AE","C4:3C:B0","44:19:B6","9C:14:63","B4:A3:FC","00:18:AE","00:40:8C","00:E0:4C","80:5E:0C"]
        if any(mac_pre.startswith(o) for o in cam_ouis):
            score += 2; oui.append("Known camera OUI")
    if score >= 2 or indicators:
        with results_lock:
            found_devices.append({"ip":ip,"mac":mac,"score":score,"ports":open_ports,"banners":list(set(banners))[:4],"rtsp":rtsp_data,"indicators":list(set(indicators))[:4],"oui":oui})

def interact_probe(ip, port=80):
    print(f"\n{'='*60}")
    print(f"INTERACTION PROBE: {ip}:{port}")
    print(f"{'='*60}")
    print(f"\n[1] Grabbing banner...")
    banners = grab_banner(ip, port)
    if banners:
        for b in banners:
            print(f"    📌 {b}")
    else:
        print("    (no banner)")
    print(f"\n[2] Trying snapshot/image URLs...")
    found_snap = False
    for brand, urls in SNAPSHOT_URLS.items():
        for url in urls:
            data = http_request(ip, port, url, timeout=4)
            if data and len(data) > 1000 and b"\xff\xd8" in data[:20]:
                print(f"    ✅ SNAPSHOT: http://{ip}:{port}{url} ({len(data)} bytes)")
                fname = f"/root/cam_snapshot_{ip.replace('.','_')}_{port}.jpg"
                try:
                    with open(fname, "wb") as f:
                        f.write(data)
                    print(f"       💾 Saved: {fname}")
                except Exception as e:
                    print(f"       ⚠️ Save failed: {e}")
                found_snap = True
                break
            elif data and b"image" in data.lower()[:200]:
                print(f"    🟡 Possible image: http://{ip}:{port}{url}")
        if found_snap:
            break
    if not found_snap:
        print("    (no open snapshots)")
    print(f"\n[3] Testing default credentials...")
    cred_found = False
    for brand, creds in DEFAULT_CREDS.items():
        for user, pwd in creds:
            data = http_request(ip, port, "/", auth=(user, pwd), timeout=2)
            if data and b"401" not in data and b"403" not in data[:50]:
                if len(data) > 500 and (b"<html" in data.lower() or b"camera" in data.lower()):
                    print(f"    ✅ CREDS WORK: {user}:{pwd} ({brand})")
                    cred_found = True
                    break
        if cred_found:
            break
    if not cred_found:
        print("    (no defaults worked)")

    print(f"\n[4] Brute-forcing RTSP paths on port 554...")
    rtsp_works = False
    for path in RTSP_PATHS[:8]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((ip, 554))
            req = f"DESCRIBE rtsp://{ip}:554{path} RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: ArgusEye\r\n\r\n"
            s.send(req.encode())
            data = s.recv(512)
            s.close()
            if data and b"200" in data:
                print(f"    ✅ RTSP STREAM: rtsp://{ip}:554{path}")
                rtsp_works = True
                break
            elif data and b"401" in data:
                print(f"    🟡 RTSP path (auth required): rtsp://{ip}:554{path}")
                rtsp_works = True
        except:
            pass
    if not rtsp_works:
        print("    (no common RTSP paths)")
    print(f"\n[5] Probing ONVIF endpoint...")
    onvif_xml = b'<?xml version="1.0"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl"/></s:Body></s:Envelope>'
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((ip, 80))
        req = b"POST /onvif/device_service HTTP/1.1\r\nHost: " + ip.encode() + b"\r\nContent-Type: application/soap+xml; charset=utf-8\r\nContent-Length: " + str(len(onvif_xml)).encode() + b"\r\n\r\n" + onvif_xml
        s.send(req)
        data = s.recv(2048)
        s.close()
        if data and b"GetDeviceInformationResponse" in data:
            print("    ✅ ONVIF responded!")
            m = re.search(b"<Model>([^<]+)</Model>", data)
            if m:
                print(f"       Model: {m.group(1).decode('utf-8','ignore')}")
        elif data and b"200" in data:
            print("    🟡 ONVIF endpoint exists")
        else:
            print("    (no ONVIF response)")
    except:
        print("    (ONVIF probe failed)")
    print(f"\n{'='*60}\nPROBE COMPLETE\n{'='*60}")

def print_banner():
    print("""
╔══════════════════════════════════════════════════════════════════╗
║     ░▒▓ ARGUS EYE v1.1 — Camera Detector + Interact ▓▒░       ║
║     For iSH / Alpine / Termux / Kali Linux                      ║
╚══════════════════════════════════════════════════════════════════╝
""")

def print_results():
    print("\n" + "="*60)
    print(f"SCAN COMPLETE — {len(found_devices)} SUSPECT DEVICE(S)")
    print("="*60)
    if not found_devices:
        print("\n[!] No camera-like devices detected.")
        print("    iSH is sandboxed — may not see real LAN devices.")
        print("    Try: Manual Target Mode (option 2) with known IP")
        return
    found_devices.sort(key=lambda x: x["score"], reverse=True)
    for i, dev in enumerate(found_devices, 1):
        risk = "🔴 HIGH" if dev["score"] >= 5 else ("🟡 MED" if dev["score"] >= 3 else "🟢 LOW")
        print(f"\n┌─[{i}] {dev['ip']:<15}  MAC: {dev['mac']:<17}  {risk}")
        print(f"│   Score: {dev['score']}/10")
        if dev["oui"]: print(f"│   OUI: {', '.join(dev['oui'])}")
        print(f"│   Ports:")
        for port, svc in dev["ports"]:
            print(f"│      → {port:<5} {svc}")
        if dev["indicators"]:
            print(f"│   Indicators:")
            for ind in dev["indicators"]:
                print(f"│      ⚡ {ind}")
        if dev["banners"]:
            print(f"│   Banners:")
            for b in dev["banners"]:
                print(f"│      📌 {b}")
        if dev["rtsp"]:
            print(f"│   RTSP:")
            for r in dev["rtsp"]:
                print(f"│   RTSP:")
            for r in dev["rtsp"]:
                print(f"│      📹 {r}")
        print("└" + "─"*55)

def network_scan():
    subnet, local_ip = get_local_subnet()
    if not subnet:
        print("[!] Could not auto-detect network.")
        subnet = input("    Subnet base (e.g. 192.168.1.): ").strip()
        if not subnet.endswith("."): subnet += "."
    else:
        print(f"[+] Local IP: {local_ip}")
        print(f"[+] Scanning: {subnet}0/24")
    mac_map = get_arp_entries()
    print(f"[+] ARP entries: {len(mac_map)}")
    print(f"[+] Scanning {len(CAMERA_PORTS)} ports x 254 hosts...")
    print(f"[+] Threads: {MAX_WORKERS} | Timeout: {TIMEOUT}s\n")
    start = time.time()
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(scan_host, f"{subnet}{i}", mac_map): i for i in range(1, 255)}
        done = 0
        for future in as_completed(futures):
            done += 1
            if done % 50 == 0:
                sys.stdout.write(f"\r    Progress: {done}/254...")
                sys.stdout.flush()
    print(f"\n[+] Done in {time.time()-start:.1f}s")
    print_results()
    if found_devices:
        print("\n[*] Run interact mode on any IP above to probe deeper.")

def manual_target():
    print("\n--- MANUAL TARGET MODE ---")
    ip = input("Enter camera IP: ").strip()
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
        print("[!] Invalid IP"); return
    port_str = input("Enter port [80] or 'all': ").strip().lower()
    if port_str == "all":
        print(f"[+] Scanning all camera ports on {ip}...")
        found = []
        for port, svc in CAMERA_PORTS.items():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                if s.connect_ex((ip, port)) == 0:
                    found.append((port, svc))
                    print(f"    ✓ Port {port} open — {svc}")
                s.close()
            except:
                pass
        if not found:
            print("    (no camera ports open)")
            return
        print(f"\n[+] {len(found)} port(s) open.")
        for port, svc in found:
            ans = input(f"    Interact with port {port}? [y/n]: ").strip().lower()
            if ans == "y":
                interact_probe(ip, port)
        return
    try:
        port = int(port_str) if port_str else 80
    except ValueError:
        print("[!] Invalid port. Use a number or 'all'")
        return
    interact_probe(ip, port)

def quick_check():
    ip = input("Enter IP to check: ").strip()
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
        print("[!] Invalid IP"); return
    print(f"\n[+] Checking {ip} for camera ports...")
    found = []
    for port, svc in CAMERA_PORTS.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            if s.connect_ex((ip, port)) == 0:
                found.append((port, svc))
                print(f"    ✓ Port {port} open — {svc}")
            s.close()
        except:
            pass
    if not found:
        print("    (no camera ports open)")
    else:
        print(f"\n[+] {len(found)} port(s) open. Run option [2] to interact.")

def main_menu():
    print_banner()
    while True:
        print("\n[1] Network Scan (auto-detect subnet)")
        print("[2] Manual Target (interact with known IP)")
        print("[3] Quick Port Check (single IP, all ports)")
        print("[0] Exit")
        choice = input("\nSelect: ").strip()
        if not choice:
            continue
        if choice == "1":
            network_scan()
        elif choice == "2":
            manual_target()
        elif choice == "3":
            quick_check()
        elif choice == "0":
            print("\nGoodbye.")
            break
        else:
            print("[!] Invalid choice")

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n\n[!] Aborted.")
        sys.exit(0)
