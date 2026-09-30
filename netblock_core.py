"""Ядро NetBlock: хранение списка, запись в hosts и правила Windows Firewall."""
import ipaddress
import json
import os
import re
import subprocess
import sys

IS_WIN = sys.platform == "win32"
HOSTS_PATH = (
    os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), r"System32\drivers\etc\hosts")
    if IS_WIN else "/tmp/hosts_test"
)
MARK_BEGIN = "# >>> NetBlock BEGIN (не редактируйте вручную) >>>"
MARK_END = "# <<< NetBlock END <<<"
RULE_PREFIX = "NetBlock"
CHUNK = 100  # IP-адресов в одном правиле файрвола

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z0-9-]{2,63}$"
)


def normalize_domain(text):
    """Из 'https://www.Example.com/path' -> 'example.com' (www убираем). None, если невалидно."""
    t = text.strip().lower()
    t = re.sub(r"^[a-z]+://", "", t)
    t = t.split("/")[0].split("?")[0].split(":")[0].strip(".")
    if t.startswith("www."):
        t = t[4:]
    try:
        t = t.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    return t if DOMAIN_RE.match(t) else None


def normalize_ip(text):
    """Принимает IP, CIDR или диапазон 'a.b.c.d-e.f.g.h'. Возвращает строку или None."""
    t = text.strip()
    try:
        if "-" in t:
            a, b = (ipaddress.ip_address(x.strip()) for x in t.split("-", 1))
            if a.version != b.version or int(a) > int(b):
                return None
            return f"{a}-{b}"
        if "/" in t:
            return str(ipaddress.ip_network(t, strict=False))
        return str(ipaddress.ip_address(t))
    except ValueError:
        return None


class Store:
    def __init__(self, path):
        self.path = path
        self.domains, self.ips, self.enabled = [], [], True
        self.routes = []  # маршруты-«чёрные дыры», добавленные приложением
        self.load()

    def load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                d = json.load(f)
            self.domains = list(d.get("domains", []))
            self.ips = list(d.get("ips", []))
            self.enabled = bool(d.get("enabled", True))
            self.routes = list(d.get("routes", []))
        except (OSError, ValueError):
            pass

    def save(self):
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump({"enabled": self.enabled, "domains": self.domains, "ips": self.ips,
                       "routes": self.routes},
                      f, ensure_ascii=False, indent=2)


# ---------- hosts ----------
def _strip_block(text):
    pat = re.compile(re.escape(MARK_BEGIN) + r".*?" + re.escape(MARK_END) + r"\r?\n?", re.S)
    return pat.sub("", text)


def _clear_readonly(path):
    """Снимает атрибут «только чтение» (Windows), если он стоит на hosts."""
    if IS_WIN and os.path.exists(path):
        import ctypes
        FILE_ATTRIBUTE_READONLY = 0x01
        attrs = ctypes.windll.kernel32.GetFileAttributesW(path)
        if attrs != -1 and attrs & FILE_ATTRIBUTE_READONLY:
            ctypes.windll.kernel32.SetFileAttributesW(path, attrs & ~FILE_ATTRIBUTE_READONLY)


def _hosts_block(domains):
    lines = [MARK_BEGIN]
    for d in domains:
        for host in (d, "www." + d):
            lines.append(f"0.0.0.0 {host}")
            lines.append(f":: {host}")
    lines.append(MARK_END)
    return lines


def hosts_in_sync(domains, hosts_path=HOSTS_PATH):
    """True, если блок в hosts совпадает с ожидаемым (или блока нет и домены не заданы)."""
    try:
        with open(hosts_path, encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        return not domains
    m = re.search(re.escape(MARK_BEGIN) + r".*?" + re.escape(MARK_END), text, re.S)
    if not domains:
        return m is None
    return m is not None and [l.strip() for l in m.group(0).splitlines()] == _hosts_block(domains)


def firewall_in_sync(ips):
    """Проверяет, что первое и последнее правила на месте (дёшево, без полного списка)."""
    if not IS_WIN or not ips:
        return True
    n = (len(ips) - 1) // CHUNK + 1
    for name in (f"{RULE_PREFIX}-out-1", f"{RULE_PREFIX}-in-{n}"):
        if _netsh("show", "rule", f"name={name}").returncode != 0:
            return False
    return True


def apply_hosts(domains, hosts_path=HOSTS_PATH):
    _clear_readonly(hosts_path)
    try:
        with open(hosts_path, encoding="utf-8", errors="replace") as f:
            text = f.read()
    except FileNotFoundError:
        text = ""
    text = _strip_block(text).rstrip() + "\n"
    if domains:
        text += "\n" + "\n".join(_hosts_block(domains)) + "\n"
    with open(hosts_path, "w", encoding="utf-8", newline="\r\n" if IS_WIN else "\n") as f:
        f.write(text)
    if IS_WIN:
        subprocess.run(["ipconfig", "/flushdns"], capture_output=True)


# ---------- firewall ----------
def _netsh(*args):
    return subprocess.run(["netsh", "advfirewall", "firewall", *args],
                          capture_output=True, text=True, errors="replace",
                          creationflags=0x08000000 if IS_WIN else 0)


def clear_firewall():
    """Удаляет ВСЕ правила NetBlock*. Через PowerShell — не зависит от языка Windows."""
    if not IS_WIN:
        return
    _ps(f"Remove-NetFirewallRule -DisplayName '{RULE_PREFIX}*' -ErrorAction SilentlyContinue")


def apply_firewall(ips):
    """Возвращает список ошибок (пустой — всё хорошо)."""
    if not IS_WIN:
        return []
    clear_firewall()
    errors = []
    for i in range(0, len(ips), CHUNK):
        part = ",".join(ips[i:i + CHUNK])
        for direction in ("out", "in"):
            name = f"{RULE_PREFIX}-{direction}-{i // CHUNK + 1}"
            r = _netsh("add", "rule", f"name={name}", f"dir={direction}",
                       "action=block", f"remoteip={part}", "enable=yes", "profile=any")
            if r.returncode != 0:
                errors.append((r.stdout or r.stderr).strip())
    return errors



# ---------- блокировка через маршруты (работает и при сторонних файрволах) ----------
ROUTE_CAP = 300


def expand_ipv4(ips):
    """IP/CIDR/диапазоны -> список IPv4-подсетей. Возвращает (nets, skipped)."""
    nets, skipped = [], []
    for t in ips:
        try:
            if "-" in t:
                a, b = (ipaddress.ip_address(x) for x in t.split("-", 1))
                if a.version != 4:
                    continue
                found = list(ipaddress.summarize_address_range(a, b))
            elif "/" in t:
                n = ipaddress.ip_network(t, strict=False)
                if n.version != 4:
                    continue
                found = [n]
            else:
                a = ipaddress.ip_address(t)
                if a.version != 4:
                    continue
                found = [ipaddress.ip_network(f"{a}/32")]
        except ValueError:
            continue
        for n in found:
            if n.prefixlen < 8:  # слишком широкие сети отрубили бы весь интернет
                skipped.append(str(n))
            elif n not in nets:
                nets.append(n)
    if len(nets) > ROUTE_CAP:
        skipped += [str(n) for n in nets[ROUTE_CAP:]]
        nets = nets[:ROUTE_CAP]
    return nets, skipped


def _route(*args):
    return subprocess.run(["route", *args], capture_output=True, text=True, errors="replace",
                          creationflags=0x08000000)


def apply_routes(old, ips):
    """Удаляет прошлые маршруты приложения и ставит новые. Возвращает (список_маршрутов, ошибки)."""
    if not IS_WIN:
        return [], []
    for n in old:
        net = ipaddress.ip_network(n)
        _route("delete", str(net.network_address), "mask", str(net.netmask))
    nets, skipped = expand_ipv4(ips)
    done, errors = [], []
    for n in nets:
        r = _route("add", str(n.network_address), "mask", str(n.netmask), "0.0.0.0", "if", "1")
        if r.returncode == 0:
            done.append(str(n))
        else:
            errors.append(f"route {n}: {(r.stdout or r.stderr).strip()[:80]}")
    if skipped:
        errors.append(f"маршрутом не заблокированы ({len(skipped)}): {', '.join(skipped[:3])}")
    return done, errors


def routes_in_sync(expected):
    if not IS_WIN or not expected:
        return True
    r = _ps("Get-NetRoute -InterfaceIndex 1 -AddressFamily IPv4 | "
            "ForEach-Object { $_.DestinationPrefix }")
    have = set(r.stdout.split())
    return all(x in have for x in expected)


def apply_all(store, hosts_path=HOSTS_PATH):
    doms = store.domains if store.enabled else []
    ips = store.ips if store.enabled else []
    apply_hosts(doms, hosts_path)
    errors = apply_firewall(ips)
    store.routes, route_errors = apply_routes(store.routes, ips)
    return errors + route_errors


def is_admin():
    if not IS_WIN:
        return os.geteuid() == 0
    import ctypes
    return bool(ctypes.windll.shell32.IsUserAnAdmin())


# ---------- автозапуск (планировщик заданий, с правами администратора) ----------
TASK_NAME = "NetBlock"


def _ps(script):
    flags = 0x08000000 if IS_WIN else 0  # CREATE_NO_WINDOW
    return subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                          capture_output=True, text=True, errors="replace", creationflags=flags)


def autostart_enabled():
    if not IS_WIN:
        return False
    flags = 0x08000000
    return subprocess.run(["schtasks", "/query", "/tn", TASK_NAME], capture_output=True,
                          creationflags=flags).returncode == 0


def set_autostart(enable, exe, args):
    """exe — путь к программе, args — строка аргументов. Возвращает текст ошибки или ''."""
    if not IS_WIN:
        return ""
    if not enable:
        r = _ps(f"Unregister-ScheduledTask -TaskName '{TASK_NAME}' -Confirm:$false")
        return "" if r.returncode == 0 else (r.stderr or r.stdout).strip()
    q = lambda x: x.replace("'", "''")
    script = (
        f"$a=New-ScheduledTaskAction -Execute '{q(exe)}' -Argument '{q(args)}';"
        "$t=New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME;"
        "$p=New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest;"
        "$s=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries "
        "-StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero);"
        f"Register-ScheduledTask -TaskName '{TASK_NAME}' -Action $a -Trigger $t -Principal $p "
        "-Settings $s -Force | Out-Null"
    )
    r = _ps(script)
    return "" if r.returncode == 0 else (r.stderr or r.stdout).strip()


# ---------- портативность ----------
_mutex = None


def single_instance():
    """False, если NetBlock уже запущен (чтобы копии из разных папок не конфликтовали)."""
    global _mutex
    if not IS_WIN:
        return True
    import ctypes
    _mutex = ctypes.windll.kernel32.CreateMutexW(None, False, "Global\\NetBlockSingleInstance")
    return ctypes.windll.kernel32.GetLastError() != 183  # ERROR_ALREADY_EXISTS


def autostart_target():
    """Путь к программе, прописанный в задании автозапуска ('' если нет)."""
    if not IS_WIN:
        return ""
    r = _ps(f"(Get-ScheduledTask -TaskName '{TASK_NAME}').Actions[0].Execute")
    return r.stdout.strip().strip('"') if r.returncode == 0 else ""


def remove_all(store):
    """Снимает все блокировки (hosts, файрвол, маршруты); сохранённый список не трогает."""
    apply_hosts([])
    clear_firewall()
    store.routes, _ = apply_routes(store.routes, [])
