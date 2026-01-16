import os
import sys
import time
import threading
from collections import deque
from datetime import datetime

win = sys.platform.startswith("win")

try:
    from scapy.all import sniff, IP, TCP, DNS
except ImportError:
    print("Установите Scapy: pip install scapy")
    sys.exit(1)

import requests
INTERFACE = None
ALERT_THRESHOLD_DNS = 30
TIME_WINDOW = 10


DANGEROUS_PORTS = {
    4444: "Metasploit reverse shell",
    1337: "Leet/backdoor port",
    6667: "IRC (часто ботнеты)",
    5555: "ADB / известные бэкдоры",
}


dns_requests = deque()
suspicious_ips = set()
whitelisted_ips = {"127.0.0.1", "0.0.0.0"}



whitelisted_domains = {
    "google.com", "gstatic.com", "googleapis.com", "googleusercontent.com",
    "microsoft.com", "windowsupdate.com", "msftncsi.com", "microsoftonline.com",
    "apple.com", "icloud.com", "apple-dns.net", "akadns.net",
    "amazonaws.com", "cloudfront.net",
    "dropbox.com", "dropboxstatic.com",
    "onedrive.com", "live.com",
    "github.com", "githubusercontent.com",
    "ubuntu.com", "canonical.com",
    "docker.com", "docker.io",
    "digicert.com", "letsencrypt.org",
    "doubleclick.net", "googlesyndication.com",
    "yandex.ru", "yandex.net", "yandex.com",
}



def is_valid_ip(ip):
    try:
        parts = ip.split('.')
        return len(parts) == 4 and all(0 <= int(x) <= 255 for x in parts)
    except:
        return False



def is_whitelisted_domain(domain):
    domain = domain.lower().rstrip('.')
    for w in whitelisted_domains:
        if domain == w or domain.endswith('.' + w):
            return True
    return False



def is_suspicious_domain(domain):
    domain = domain.lower().rstrip('.')
    if domain.endswith('.local'):
        return False
    if len(domain) > 60:
        return True
    labels = domain.split('.')
    if len(labels) >= 2 and len(labels[0]) > 30:
        return True
    first_label = labels[0]
    if first_label.isalnum() and not first_label.isalpha() and not first_label.isdigit():
        if len(first_label) >= 10 and sum(c.isdigit() for c in first_label) > 3:
            return True
    return False



def alert(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[ALERT] {timestamp} — {message}")
    with open("alerts.log", "a", encoding="utf-8") as f:
        f.write(f"{timestamp} — {message}\n")



def load_malicious_ips():
    print("Загружаем чёрный список IP (Feodo Tracker)...")
    try:
        url = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv    "
        response = requests.get(url, timeout=10)
        lines = response.text.splitlines()
        for line in lines:
            if line and not line.startswith('#') and not line.startswith('first_seen'):
                parts = line.split(',')
                if len(parts) > 1:
                    ip = parts[1].strip('"')
                    if is_valid_ip(ip):
                        suspicious_ips.add(ip)
        print(f"Загружено {len(suspicious_ips)} подозрительных IP.")
    except Exception as e:
        print(f"Ошибка загрузки чёрного списка: {e}")



def packet_handler(packet):
    if IP not in packet:
        return
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    if src_ip in whitelisted_ips or dst_ip in whitelisted_ips:
        return
    if dst_ip == "224.0.0.251":
        return
    if dst_ip in suspicious_ips:
        alert(f"Подозрительное соединение с известным вредоносным IP: {dst_ip} (Feodo Tracker)")
    if TCP in packet:
        dst_port = packet[TCP].dport
        if dst_port in DANGEROUS_PORTS:
            reason = DANGEROUS_PORTS[dst_port]
            alert(f"Соединение на подозрительный порт {dst_port} ({reason}) — IP: {dst_ip}, источник: {src_ip}")
    if DNS in packet and packet[DNS].qr == 0 and packet[DNS].qd:
        try:
            qname = packet[DNS].qd.qname
            if isinstance(qname, bytes):
                domain = qname.decode('utf-8', errors='ignore').rstrip('.')
            else:
                domain = str(qname).rstrip('.')
        except Exception:
            return
        if domain.endswith('.local'):
            return
        if is_whitelisted_domain(domain):
            return
        now = time.time()
        while dns_requests and now - dns_requests[0][0] > TIME_WINDOW:
            dns_requests.popleft()
        if is_suspicious_domain(domain):
            alert(f"Подозрительное DNS-имя (эвристика): {domain} → IP: {dst_ip}")
        dns_requests.append((now, domain))
        if len(dns_requests) >= ALERT_THRESHOLD_DNS:
            unique_domains = {d for _, d in dns_requests}
            if len(unique_domains) >= ALERT_THRESHOLD_DNS // 2:
                alert(f"Аномальная DNS-активность: {len(dns_requests)} запросов "
                      f"({len(unique_domains)} уникальных) за {TIME_WINDOW} сек! "
                      f"Последний: {domain}")



def main():
    print("Запуск анализатора сетевого трафика...")
    if win:
        print("Вы используете Windows. Убедитесь, что установлен Npcap!")
    else:
        print("Для полного доступа к пакетам запустите от root (sudo).")
    print("Нажмите Ctrl+C для остановки.\n")
    blacklist_thread = threading.Thread(target=load_malicious_ips, daemon=True)
    blacklist_thread.start()
    time.sleep(2)
    try:
        sniff(
            iface=INTERFACE,
            prn=packet_handler,
            store=False,
            filter="ip"
        )
    except KeyboardInterrupt:
        print("\n Сниффинг остановлен.")
    except PermissionError:
        if win:
            print(" Ошибка: запустите от имени Администратора.")
        else:
            print(" Ошибка: запустите через sudo.")
    except Exception as e:
        print(f" Ошибка: {e}")


        
if __name__ == "__main__":
    main()