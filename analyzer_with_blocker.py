import os
import sys
import time
import threading
import subprocess
from collections import deque
from datetime import datetime
from queue import Queue
import hashlib
import atexit
import signal

# Определяем ОС
IS_WINDOWS = sys.platform.startswith("win")
IS_LINUX = sys.platform.startswith("linux")

try:
    from scapy.all import sniff, IP, TCP, DNS, get_if_list
except ImportError:
    print("Установите Scapy: pip install scapy")
    sys.exit(1)

try:
    import requests
except ImportError:
    print("Установите requests: pip install requests")
    sys.exit(1)

# ====== НАСТРОЙКИ ======
INTERFACE = None
ALERT_THRESHOLD_DNS = 30
TIME_WINDOW = 10
INTERACTIVE_MODE = True
DEDUPLICATION_WINDOW = 30  # секунд — не показывать повторы за это время

DANGEROUS_PORTS = {
    4444: "Metasploit reverse shell",
    1337: "Leet/backdoor port",
    6667: "IRC (часто ботнеты)",
    5555: "ADB / известные бэкдоры",
    8443: "Нестандартный HTTPS (часто C2)"
}

whitelisted_ips = {"127.0.0.1", "0.0.0.0"}
suspicious_ips = set()
blocked_ips = set()

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

dns_requests = deque()
block_queue = Queue()
stop_event = threading.Event()

# Анти-повтор
seen_events = deque()  # [(timestamp, hash), ...]

def is_duplicate_event(event_key):
    now = time.time()
    while seen_events and now - seen_events[0][0] > DEDUPLICATION_WINDOW:
        seen_events.popleft()
    event_hash = hashlib.md5(event_key.encode()).hexdigest()
    for _, h in seen_events:
        if h == event_hash:
            return True
    seen_events.append((now, event_hash))
    return False

# ====== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ======

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

# ====== БЛОКИРОВКА ======

def block_ip(ip):
    if not is_valid_ip(ip) or ip in whitelisted_ips or ip in blocked_ips:
        return
    if IS_WINDOWS:
        block_ip_windows(ip)
    elif IS_LINUX:
        block_ip_linux(ip)
    else:
        alert(f"Блокировка не поддерживается на этой ОС для IP: {ip}")
    blocked_ips.add(ip)

def block_ip_linux(ip):
    try:
        result = subprocess.run(
            ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True
        )
        if result.returncode != 0:
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            subprocess.run(["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"], check=True)
            alert(f"IP {ip} заблокирован через iptables!")
        else:
            print(f"[INFO] IP {ip} уже заблокирован.")
    except Exception as e:
        print(f"[ERROR] Не удалось заблокировать {ip}: {e}")

def block_ip_windows(ip):
    rule_name_in = f"Block_Malicious_IP_IN_{ip.replace('.', '_')}"
    rule_name_out = f"Block_Malicious_IP_OUT_{ip.replace('.', '_')}"

    try:
        check_cmd = [
            "powershell", "-Command",
            f"Get-NetFirewallRule -DisplayName '{rule_name_in}' -ErrorAction SilentlyContinue"
        ]
        result = subprocess.run(check_cmd, capture_output=True, text=True)
        if result.stdout.strip():
            print(f"[INFO] IP {ip} уже заблокирован.")
            return

        cmd_in = [
            "powershell", "-Command",
            f"New-NetFirewallRule -DisplayName '{rule_name_in}' -Direction Inbound -RemoteAddress {ip} -Action Block"
        ]
        cmd_out = [
            "powershell", "-Command",
            f"New-NetFirewallRule -DisplayName '{rule_name_out}' -Direction Outbound -RemoteAddress {ip} -Action Block"
        ]
        subprocess.run(cmd_in, check=True, capture_output=True)
        subprocess.run(cmd_out, check=True, capture_output=True)
        alert(f"IP {ip} заблокирован через Windows Firewall!")
    except Exception as e:
        print(f"[ERROR] Не удалось заблокировать {ip}: {e}")

def cleanup_firewall_rules():
    if IS_WINDOWS:
        try:
            cmd = [
                "powershell", "-Command",
                "Get-NetFirewallRule -DisplayName 'Block_Malicious_IP_*' | Remove-NetFirewallRule -Confirm:$false"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                print("Все правила Windows Firewall удалены.")
            else:
                print(f"Ошибка при очистке: {result.stderr}")
        except Exception as e:
            print(f"Ошибка очистки: {e}")
    elif IS_LINUX:
        print("Правила iptables будут сброшены после перезагрузки.")

# ====== НАДЕЖНАЯ ОЧИСТКА ======

def safe_cleanup():
    """Потокобезопасная и идемпотентная очистка"""
    if getattr(safe_cleanup, "already_run", False):
        return
    safe_cleanup.already_run = True

    print("\nВыполняется очистка...")
    cleanup_firewall_rules()

# Регистрируем очистку при штатном завершении
atexit.register(safe_cleanup)

# Обработка сигналов (частично работает на Windows)
def signal_handler(signum, frame):
    print(f"\nПолучен сигнал {signum}. Завершение...")
    stop_event.set()
    safe_cleanup()
    sys.exit(0)

if hasattr(signal, 'SIGINT'):
    signal.signal(signal.SIGINT, signal_handler)
if hasattr(signal, 'SIGTERM'):
    signal.signal(signal.SIGTERM, signal_handler)

# ====== МЕНЮ ПОДТВЕРЖДЕНИЯ ======

def confirmation_menu():
    while not stop_event.is_set():
        try:
            item = block_queue.get(timeout=1)
            threat_type, ip, details = item

            print("\n" + "="*60)
            print(f"Обнаружена подозрительная активность!")
            print(f"Тип: {threat_type}")
            print(f"IP: {ip}")
            print(f"Детали: {details}")
            print("\nЗаблокировать соединение с этим IP?")
            print("[1] Да, заблокировать")
            print("[2] Нет, пропустить")
            print("[3] Заблокировать и не спрашивать больше (авто)")
            print("="*60)

            try:
                choice = input("Ваш выбор (1/2/3): ").strip()
            except EOFError:
                choice = "2"

            if choice == "1":
                block_ip(ip)
            elif choice == "3":
                global INTERACTIVE_MODE
                INTERACTIVE_MODE = False
                block_ip(ip)
                print("Переключено в автоматический режим блокировки.")
            else:
                print("Пропущено.")

            block_queue.task_done()
        except:
            continue

# ====== ЗАГРУЗКА ЧЁРНОГО СПИСКА ======

def load_malicious_ips():
    print("Загружаем чёрный список IP (Feodo Tracker)...")
    try:
        url = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        lines = response.text.splitlines()
        count = 0
        for line in lines:
            if line and not line.startswith('#') and not line.startswith('first_seen'):
                parts = line.split(',')
                if len(parts) > 1:
                    ip = parts[1].strip('"')
                    if is_valid_ip(ip):
                        suspicious_ips.add(ip)
                        count += 1
        print(f"Загружено {count} подозрительных IP.")
    except Exception as e:
        print(f"Ошибка загрузки чёрного списка: {e}")

# ====== АНАЛИЗ TLS/SNI ======

def parse_sni_from_tls(payload):
    try:
        if len(payload) < 40:
            return None
        if payload[0] != 0x16 or payload[1] != 0x03:
            return None
        if payload[5] != 0x01:
            return None

        from io import BytesIO
        data = BytesIO(payload[5:])
        data.read(1); data.read(2); data.read(32)
        session_id_len = ord(data.read(1)); data.read(session_id_len)
        cipher_len = int.from_bytes(data.read(2), 'big'); data.read(cipher_len)
        comp_len = ord(data.read(1)); data.read(comp_len)
        if data.tell() >= len(payload) - 5:
            return None
        ext_len = int.from_bytes(data.read(2), 'big')
        extensions = data.read(ext_len)

        i = 0
        while i < len(extensions):
            if i + 4 > len(extensions):
                break
            ext_type = int.from_bytes(extensions[i:i+2], 'big')
            ext_size = int.from_bytes(extensions[i+2:i+4], 'big')
            if ext_type == 0x0000:
                sni_data = extensions[i+4:i+4+ext_size]
                if len(sni_data) < 5:
                    return None
                name_len = int.from_bytes(sni_data[3:5], 'big')
                if 5 + name_len > len(sni_data):
                    return None
                sni = sni_data[5:5+name_len].decode('utf-8')
                return sni
            i += 4 + ext_size
    except Exception:
        return None
    return None

# ====== ОБРАБОТЧИК ПАКЕТОВ ======

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
        msg = f"Подозрительное соединение с известным вредоносным IP: {dst_ip} (Feodo Tracker)"
        event_key = f"malicious_ip|{dst_ip}"
        if not is_duplicate_event(event_key):
            alert(msg)
            if INTERACTIVE_MODE:
                block_queue.put(("Известный вредоносный IP", dst_ip, msg))
            else:
                block_ip(dst_ip)

    if TCP in packet:
        dst_port = packet[TCP].dport
        payload = bytes(packet[TCP].payload)

        if dst_port in DANGEROUS_PORTS:
            reason = DANGEROUS_PORTS[dst_port]
            msg = f"Соединение на подозрительный порт {dst_port} ({reason}) — IP: {dst_ip}, источник: {src_ip}"
            event_key = f"dangerous_port|{dst_ip}|{dst_port}"
            if not is_duplicate_event(event_key):
                alert(msg)
                if INTERACTIVE_MODE:
                    block_queue.put(("Опасный порт", dst_ip, msg))
                else:
                    block_ip(dst_ip)

        if (dst_port == 443 or dst_port in DANGEROUS_PORTS) and len(payload) > 40:
            sni = parse_sni_from_tls(payload)
            if sni and not sni.endswith('.local') and not is_whitelisted_domain(sni):
                if is_suspicious_domain(sni):
                    msg = f"Подозрительное HTTPS-соединение (SNI): {sni} → IP: {dst_ip}"
                    event_key = f"sni|{sni}|{dst_ip}"
                    if not is_duplicate_event(event_key):
                        alert(msg)
                        if INTERACTIVE_MODE:
                            block_queue.put(("Подозрительный SNI", dst_ip, msg))
                        else:
                            block_ip(dst_ip)

    if DNS in packet and packet[DNS].qr == 0 and packet[DNS].qd:
        try:
            qname = packet[DNS].qd.qname
            domain = qname.decode('utf-8', errors='ignore').rstrip('.') if isinstance(qname, bytes) else str(qname).rstrip('.')
        except Exception:
            return

        if domain.endswith('.local') or is_whitelisted_domain(domain):
            return

        now = time.time()
        while dns_requests and now - dns_requests[0][0] > TIME_WINDOW:
            dns_requests.popleft()

        if is_suspicious_domain(domain):
            msg = f"Подозрительное DNS-имя (эвристика): {domain} → IP: {dst_ip}"
            event_key = f"suspicious_dns|{domain}"
            if not is_duplicate_event(event_key):
                alert(msg)

        dns_requests.append((now, domain))

        if len(dns_requests) >= ALERT_THRESHOLD_DNS:
            unique_domains = {d for _, d in dns_requests}
            if len(unique_domains) >= ALERT_THRESHOLD_DNS // 2:
                msg = f"Аномальная DNS-активность: {len(dns_requests)} запросов ({len(unique_domains)} уникальных) за {TIME_WINDOW} сек! Последний: {domain}"
                event_key = f"dns_flood|{src_ip}"
                if not is_duplicate_event(event_key):
                    alert(msg)
                    if INTERACTIVE_MODE:
                        block_queue.put(("Аномальный DNS-трафик", src_ip, msg))
                    else:
                        block_ip(src_ip)

# ====== ОСНОВНАЯ ФУНКЦИЯ ======

def main():
    global INTERACTIVE_MODE

    # Режим ручной очистки
    if "--cleanup" in sys.argv:
        print("Режим ручной очистки запущен...")
        cleanup_firewall_rules()
        return

    print("Запуск анализатора сетевого трафика...")
    print("Режим: " + ("интерактивный (с подтверждением)" if INTERACTIVE_MODE else "автоматический"))
    if IS_WINDOWS:
        print("Запустите от имени АДМИНИСТРАТОРА!")
    elif IS_LINUX:
        print("Запустите через sudo!")

    print("\nУправление:")
    print("   В PyCharm: нажмите Ctrl+F2 для остановки")
    print("   В консоли: Ctrl+C\n")

    try:
        interfaces = get_if_list()
        print(f"Доступные интерфейсы: {interfaces}")
        if not INTERFACE and interfaces:
            print("Будет использован интерфейс по умолчанию.")
    except Exception as e:
        print(f"Не удалось получить список интерфейсов: {e}")

    menu_thread = threading.Thread(target=confirmation_menu, daemon=True)
    menu_thread.start()

    blacklist_thread = threading.Thread(target=load_malicious_ips, daemon=True)
    blacklist_thread.start()
    time.sleep(2)

    try:
        print("Начало сниффинга...")
        while not stop_event.is_set():
            sniff(
                iface=INTERFACE,
                prn=packet_handler,
                store=False,
                filter="ip",
                timeout=0.5,
                stop_filter=lambda p: stop_event.is_set()
            )
    except KeyboardInterrupt:
        print("\nПолучен KeyboardInterrupt. Завершение...")
        stop_event.set()
        safe_cleanup()
        return
    except PermissionError:
        if IS_WINDOWS:
            print("Запустите от имени Администратора!")
        else:
            print("Запустите через sudo!")
        safe_cleanup()
        return
    except Exception as e:
        print(f"Неожиданная ошибка: {e}")
        safe_cleanup()
        return

if __name__ == "__main__":
    main()
