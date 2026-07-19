#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import aiohttp
import re
import base64
import os
import time
import logging
import ipaddress
import socket
import json
from datetime import datetime, timezone
from html import unescape as html_unescape
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("whitevless")

BASE_DIR        = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE     = os.path.join(BASE_DIR, "filtered_vless_keys.txt")
OUTPUT_FILE_2   = os.path.join(BASE_DIR, "filtered_vless_keys_2.txt")
DIRECT_FILE     = os.path.join(BASE_DIR, "sources", "direct.txt")
TEST_FILE       = os.path.join(BASE_DIR, "sources", "Test.txt")
BLACKLIST_FILE  = os.path.join(BASE_DIR, "blacklist", "vless_blacklist.txt")
CLASH_FILE      = os.path.join(BASE_DIR, "clash.yaml")
ROUTING_PROFILES_FILE = os.path.join(BASE_DIR, "routing_profiles", "profiles.json")

MAX_KEYS     = 200
MAX_KEYS_2   = 300
MAX_PER_HOST = 3
TCP_TIMEOUT  = 6.0
CONCURRENCY  = 80

_RU_NETWORKS_RAW = [
    "158.160.0.0/16", "130.193.32.0/19", "51.250.0.0/16", "84.201.128.0/17",
    "84.23.52.0/22", "95.163.248.0/22", "79.137.174.0/23", "37.139.32.0/22", "90.156.151.0/24",
    "5.188.136.0/21", "5.188.140.0/24",
    "95.213.128.0/17", "92.53.64.0/19", "77.244.208.0/20", "188.225.0.0/18", "178.236.128.0/20",
    "178.250.240.0/21",
]
RU_NETWORKS = [ipaddress.ip_network(n, strict=False) for n in _RU_NETWORKS_RAW]

SELECTEL_RANGES = [
    ipaddress.ip_network("36.46.0.0/16", strict=False),
    ipaddress.ip_network("45.153.0.0/16", strict=False),
]

UUID_RE   = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$', re.I)
ARABIC_RE = re.compile(r'[\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF\uFB50-\uFDFF\uFE70-\uFEFF]')
SPAM_RE   = re.compile(r'(t\.me|telegram\.(me|org|dog)|@[\w_]{3,}|купить|прода)', re.I)

BLOCKLIST_EXACT:   set[str] = set()
BLOCKLIST_PARTIAL: set[str] = set()


def _ip_in_ru_networks(host: str) -> bool:
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        try:
            addr = ipaddress.ip_address(socket.gethostbyname(host))
        except Exception:
            return False
    return any(addr in net for net in RU_NETWORKS)


def _is_selectel(host: str) -> bool:
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        try:
            addr = ipaddress.ip_address(socket.gethostbyname(host))
        except Exception:
            return False
    return any(addr in net for net in SELECTEL_RANGES)


def _lines(path):
    if not os.path.exists(path): return []
    with open(path, encoding="utf-8", errors="ignore") as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]


def load_blocklist():
    if not os.path.exists(BLACKLIST_FILE): return
    with open(BLACKLIST_FILE, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"): continue
            if line.startswith("vless://"):
                BLOCKLIST_EXACT.add(line.split("#")[0].lower())
            else:
                BLOCKLIST_PARTIAL.add(line.lower())
    log.info(f"blocklist: exact={len(BLOCKLIST_EXACT)}, partial={len(BLOCKLIST_PARTIAL)}")


def _extract(link, part):
    try:
        p = urlparse(link)
        if part == "host": return p.hostname or ""
        if part == "port": return p.port if p.port and 1 <= p.port <= 65535 else 0
        if part == "params": return {k: v[0] for k, v in parse_qs(p.query).items()}
    except: pass
    return "" if part != "port" else 0


def _valid_uuid(u):
    return bool(UUID_RE.match(u)) if u else False


def _is_blocked(key):
    base = key.split("#")[0].lower()
    if base in BLOCKLIST_EXACT: return True
    return any(p in key.lower() for p in BLOCKLIST_PARTIAL)


def _clean(raw):
    key = raw.strip()
    if not key.startswith("vless://"): return None
    if len(key) > 1000: return None
    base = ARABIC_RE.sub("", key.split("#")[0])
    if SPAM_RE.search(base): return None
    if _is_blocked(key): return None
    try:
        p = urlparse(base)
        if not _valid_uuid(p.username or ""): return None
        if not p.hostname or not p.port: return None
        if not (1 <= p.port <= 65535): return None
    except: return None
    params = {k: v[0] for k, v in parse_qs(urlparse(base).query).items()}
    if params.get("encryption", "none") != "none": return None
    if "pqv" in params: return None
    if params.get("security") == "reality" and "fp" not in params:
        params["fp"] = "chrome"
        base = urlunparse(urlparse(base)._replace(query=urlencode(params)))
    return base


def _parse_text(text):
    text = html_unescape(text)
    text = re.sub(r'&amp%3B|%26amp%3B', '&', text, flags=re.I)
    stripped = text.strip()
    if stripped and "vless://" not in stripped[:200]:
        try:
            decoded = base64.b64decode(stripped + "==").decode("utf-8", errors="ignore")
            if "vless://" in decoded:
                text = decoded
        except: pass
    keys = []
    for line in text.splitlines():
        line = line.strip()
        candidates = [line] if line.startswith("vless://") else re.findall(r'vless://[^\s\'"<>\]\[]+', line)
        for c in candidates:
            k = _clean(c)
            if k: keys.append(k)
    return keys


async def _get(session, url):
    try:
        async with session.get(url, headers={"Accept": "text/plain, */*"},
                               timeout=aiohttp.ClientTimeout(total=25)) as r:
            if r.status == 200:
                return await r.text(errors="ignore")
            log.debug(f"fetch {url}: status {r.status}")
    except Exception as e:
        log.debug(f"fetch {url}: {e}")
    return ""


async def fetch_direct(session):
    urls = [u for u in _lines(DIRECT_FILE) if u.startswith("http")]
    if not urls: return []
    log.info(f"direct sources: {len(urls)}")
    texts = await asyncio.gather(*[_get(session, u) for u in urls])
    keys = []
    for url, text in zip(urls, texts):
        found = _parse_text(text)
        log.info(f"  {url.split('/')[-1][:50]}: {len(found)} keys")
        keys.extend(found)
    return keys


async def fetch_test(session):
    urls = [u for u in _lines(TEST_FILE) if u.startswith("http")]
    if not urls: return []
    log.info(f"[sub2] test sources: {len(urls)}")
    texts = await asyncio.gather(*[_get(session, u) for u in urls])
    keys = []
    for url, text in zip(urls, texts):
        found = _parse_text(text)
        log.info(f"  [sub2] {url.split('/')[-1][:50]}: {len(found)} keys")
        keys.extend(found)
    return keys


async def tcp_check(host, port) -> float:
    try:
        start = time.monotonic()
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=TCP_TIMEOUT)
        writer.close()
        try: await writer.wait_closed()
        except: pass
        return (time.monotonic() - start) * 1000
    except: return -1.0


async def tls_check(host, port, sni) -> float:
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        start = time.monotonic()
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=sni), timeout=TCP_TIMEOUT)
        writer.close()
        try: await writer.wait_closed()
        except: pass
        return (time.monotonic() - start) * 1000
    except: return -1.0


async def probe_key(key) -> float:
    host   = _extract(key, "host")
    port   = _extract(key, "port")
    params = _extract(key, "params")
    if not host or not port: return -1.0

    sec = params.get("security", "")
    sni = params.get("sni", "")

    if sec in ("reality", "tls") and sni:
        lat = await tls_check(host, port, sni)
        if lat > 0: return lat
        return await tcp_check(host, port)

    try:
        start = time.monotonic()
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=TCP_TIMEOUT)
        writer.write(b"\x00")
        await writer.drain()
        try:
            await asyncio.wait_for(reader.read(1), timeout=1.0)
        except asyncio.TimeoutError:
            pass
        writer.close()
        try: await writer.wait_closed()
        except: pass
        return (time.monotonic() - start) * 1000
    except: return -1.0


async def check_batch(keys, sem):
    async def _one(key):
        async with sem:
            lat = await probe_key(key)
        if lat < 0: return None
        return (lat, key)
    results = await asyncio.gather(*[_one(k) for k in keys])
    return sorted([r for r in results if r], key=lambda x: x[0])


GEO_CACHE: dict[str, dict] = {}


def _cc_flag(cc):
    if len(cc) != 2: return "🌐"
    return chr(ord(cc[0]) + 127397) + chr(ord(cc[1]) + 127397)


async def geo_lookup(session, hosts):
    unique = list(dict.fromkeys(hosts))
    for i in range(0, len(unique), 100):
        chunk = unique[i:i+100]
        try:
            payload = [{"query": h, "fields": "query,countryCode,isp,org"} for h in chunk]
            async with session.post("http://ip-api.com/batch", json=payload,
                                    timeout=aiohttp.ClientTimeout(total=15)) as r:
                if r.status == 200:
                    for item in await r.json(content_type=None):
                        h   = item.get("query", "")
                        cc  = item.get("countryCode", "")
                        isp = item.get("isp", "") or item.get("org", "")
                        isp = re.sub(r'\s*\(.*?\)', '', isp).strip()[:45]
                        GEO_CACHE[h] = {"cc": cc, "isp": isp, "flag": _cc_flag(cc)}
        except Exception as e: log.debug(f"geo batch: {e}")
        await asyncio.sleep(1.0)


_COUNTER = {"n": 0}


def _build_remark(key, lat):
    host   = _extract(key, "host")
    geo    = GEO_CACHE.get(host, {})
    flag   = geo.get("flag", "🌐")
    isp    = geo.get("isp", "")
    params = _extract(key, "params")
    sec    = params.get("security", "")
    tp     = params.get("type", "tcp")

    if sec == "reality":
        prefix = "LTE"
    elif tp in ("ws", "websocket", "grpc", "xhttp"):
        prefix = "Универсальный"
    else:
        prefix = "Сервер"

    _COUNTER["n"] += 1
    isp_short = isp.split()[0][:14] if isp else host[:14]
    
    if _is_selectel(host):
        suffix = " | Не для ТГ, ТТ"
    else:
        suffix = ""
    
    return f"{flag} {prefix} | {isp_short}{suffix} | #{_COUNTER['n']}"


def _b64e(s): return base64.b64encode(s.encode()).decode()


def _make_announce(updated_at: str) -> str:
    return (
        f"🕐 Обновлено: {updated_at} UTC\n\n"
        "Поддержка ВОЗОБНОВЛЕНА!!!!\n"
        "Парсер будет работать!!!\n"
        "\n\n"
    )


def write_output(keys_with_lat):
    updated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
    announce = _make_announce(updated_at)
    header = "\n".join([
        f"#profile-title: base64:{_b64e('👾WhiteVless')}",
        "#profile-update-interval: 2",
        "#support-url: https://github.com/plsn1337/white-vless/",
        "#profile-web-page-url: https://github.com/plsn1337/white-vless/",
        f"#announce: base64:{_b64e(announce)}", "",
    ])
    _COUNTER["n"] = 0
    lines = []
    for lat, key in keys_with_lat:
        lines.append(f"{key}#{quote(_build_remark(key, lat))}")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(header)
        for l in lines: f.write(l + "\n")
    log.info(f"written {len(lines)} keys → {OUTPUT_FILE}")


def write_output_2(keys_with_lat):
    updated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
    announce = _make_announce(updated_at)
    header = "\n".join([
        f"#profile-title: base64:{_b64e('👾WhiteVless RU')}",
        "#profile-update-interval: 2",
        "#support-url: https://github.com/plsn1337/white-vless/",
        "#profile-web-page-url: https://github.com/plsn1337/white-vless/",
        f"#announce: base64:{_b64e(announce)}", "",
    ])
    _COUNTER["n"] = 0
    lines = []
    for lat, key in keys_with_lat:
        lines.append(f"{key}#{quote(_build_remark(key, lat))}")
    with open(OUTPUT_FILE_2, "w", encoding="utf-8") as f:
        f.write(header)
        for l in lines: f.write(l + "\n")
    log.info(f"[sub2] written {len(lines)} keys → {OUTPUT_FILE_2}")


def _build_clash_config(keys_with_lat, clash_file, title):
    def _proxy(key, name):
        try:
            p = urlparse(key)
            params = {k: v[0] for k, v in parse_qs(p.query).items()}
            sec = params.get("security", "")
            tp  = params.get("type", "tcp")
            proxy = {"name": name, "type": "vless", "server": p.hostname,
                     "port": p.port, "uuid": p.username, "udp": True}
            flow = params.get("flow", "")
            if flow: proxy["flow"] = flow
            if sec == "reality":
                proxy.update({"tls": True, "servername": params.get("sni", ""),
                    "reality-opts": {"public-key": params.get("pbk", ""), "short-id": params.get("sid", "")},
                    "client-fingerprint": params.get("fp", "chrome")})
            elif sec == "tls":
                proxy.update({"tls": True, "servername": params.get("sni", ""), "skip-cert-verify": True})
            if tp == "ws":
                proxy["network"] = "ws"
                proxy["ws-opts"] = {"path": params.get("path", "/"), "headers": {"Host": params.get("host", p.hostname)}}
            elif tp == "grpc":
                proxy["network"] = "grpc"
                proxy["grpc-opts"] = {"grpc-service-name": params.get("serviceName", "")}
            elif tp in ("xhttp", "http"):
                proxy["network"] = "http"
                proxy["http-opts"] = {"path": [params.get("path", "/")]}
            return proxy
        except: return None

    def _yv(v):
        if isinstance(v, bool): return "true" if v else "false"
        if isinstance(v, (int, float)): return str(v)
        s = str(v)
        if any(c in s for c in ':{}[]|>&*!,#?@`\'"') or not s: return f'"{s}"'
        return s

    def _yaml(obj, indent=0):
        pad = "  " * indent
        if isinstance(obj, dict):
            out = []
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    out.append(f"{pad}{k}:"); out.append(_yaml(v, indent+1))
                else:
                    out.append(f"{pad}{k}: {_yv(v)}")
            return "\n".join(out)
        elif isinstance(obj, list):
            out = []
            for item in obj:
                if isinstance(item, dict):
                    items = list(item.items()); fk, fv = items[0]
                    if isinstance(fv, (dict, list)):
                        out.append(f"{pad}- {fk}:"); out.append(_yaml(fv, indent+2))
                    else:
                        out.append(f"{pad}- {fk}: {_yv(fv)}")
                    for k, v in items[1:]:
                        if isinstance(v, (dict, list)):
                            out.append(f"{pad}  {k}:"); out.append(_yaml(v, indent+2))
                        else:
                            out.append(f"{pad}  {k}: {_yv(v)}")
                else:
                    out.append(f"{pad}- {_yv(item)}")
            return "\n".join(out)
        return f"{pad}{_yv(obj)}"

    proxies, names = [], []
    _COUNTER["n"] = 0
    for lat, key in keys_with_lat:
        name = _build_remark(key, lat)
        base = name; i = 1
        while name in names: name = f"{base} ({i})"; i += 1
        px = _proxy(key, name)
        if px: proxies.append(px); names.append(name)

    if not proxies: return

    cfg = {
        "mixed-port": 7890, "allow-lan": False, "mode": "rule",
        "log-level": "warning", "external-controller": "127.0.0.1:9090",
        "proxies": proxies,
        "proxy-groups": [
            {"name": "🚀 Авто", "type": "url-test", "proxies": names,
             "url": "https://www.gstatic.com/generate_204", "interval": 180, "tolerance": 50},
            {"name": "🔀 Выбор", "type": "select", "proxies": ["🚀 Авто"] + names},
        ],
        "rules": ["GEOIP,RU,DIRECT", "MATCH,🔀 Выбор"],
    }
    with open(clash_file, "w", encoding="utf-8") as f:
        f.write(f"# {title} — Clash Meta config\n")
        f.write(_yaml(cfg) + "\n")
    log.info(f"written clash: {len(proxies)} proxies → {clash_file}")


def write_clash(keys_with_lat):
    _build_clash_config(keys_with_lat, CLASH_FILE, "WhiteVless")


def add_routing_profiles():
    if not os.path.exists(ROUTING_PROFILES_FILE):
        log.warning(f"routing profiles file not found: {ROUTING_PROFILES_FILE}")
        return
    
    try:
        with open(ROUTING_PROFILES_FILE, "r", encoding="utf-8") as f:
            profiles = json.load(f)
        
        routing_profiles = [p for p in profiles if p.get("type") == "routing"]
        control_profiles = [p for p in profiles if p.get("type") == "control"]
        
        log.info(f"routing profiles: {len(routing_profiles)} routing, {len(control_profiles)} control")
        
        for profile in routing_profiles:
            name = profile.get("name", "Unknown")
            description = profile.get("description", "")
            auto_apply = " (auto)" if profile.get("auto_apply") else ""
            log.info(f"  🔀 {name}{auto_apply}: {description}")
        
        for profile in control_profiles:
            name = profile.get("name", "Unknown")
            description = profile.get("description", "")
            log.info(f"  ⚙️  {name}: {description}")
    except Exception as e:
        log.error(f"error loading routing profiles: {e}")


def _dedup(keys):
    seen_ep, host_count, result = set(), {}, []
    for key in keys:
        host = _extract(key, "host")
        ep   = f"{host}:{_extract(key, 'port')}"
        if ep in seen_ep: continue
        if host_count.get(host, 0) >= MAX_PER_HOST: continue
        seen_ep.add(ep)
        host_count[host] = host_count.get(host, 0) + 1
        result.append(key)
    return result


async def main():
    load_blocklist()
    add_routing_profiles()

    connector = aiohttp.TCPConnector(limit=150, ssl=False)
    ua = {"User-Agent": "Happ/3.18.3/Happ/2.8.0/Windows/22226661337228"}

    async with aiohttp.ClientSession(connector=connector, headers=ua) as session:

        all_keys = await fetch_direct(session)
        log.info(f"collected: {len(all_keys)}")

        deduped = _dedup(all_keys)
        log.info(f"after dedup: {len(deduped)}")

        sem = asyncio.Semaphore(CONCURRENCY)
        alive = await check_batch(deduped, sem)
        log.info(f"alive: {len(alive)}")

        selected = alive[:MAX_KEYS]
        await geo_lookup(session, list(dict.fromkeys(_extract(k, "host") for _, k in selected)))

        write_output(selected)
        write_clash(selected)
        log.info(f"sub1 done: {len(selected)} keys")

        log.info("=" * 60)
        all_keys_2 = await fetch_test(session)
        log.info(f"[sub2] collected: {len(all_keys_2)}")

        if not all_keys_2:
            log.info("[sub2] no sources in Test.txt, skipping")
            return

        unique_hosts = list(dict.fromkeys(_extract(k, "host") for k in all_keys_2 if _extract(k, "host")))
        log.info(f"[sub2] resolving {len(unique_hosts)} unique hosts...")
        loop = asyncio.get_event_loop()
        sem_dns = asyncio.Semaphore(200)

        async def _check_host(host):
            async with sem_dns:
                return host, await loop.run_in_executor(None, _ip_in_ru_networks, host)

        results = await asyncio.gather(*[_check_host(h) for h in unique_hosts])
        ru_hosts = {h for h, ok in results if ok}
        log.info(f"[sub2] hosts in RU ranges: {len(ru_hosts)}")

        ru_filtered = [k for k in all_keys_2 if _extract(k, "host") in ru_hosts]
        log.info(f"[sub2] after RU IP filter: {len(ru_filtered)}")

        deduped2 = _dedup(ru_filtered)
        log.info(f"[sub2] after dedup: {len(deduped2)}")

        def _port_priority(key):
            port = _extract(key, "port")
            return 0 if port == 443 else port

        selected2 = sorted(deduped2, key=_port_priority)[:MAX_KEYS_2]
        log.info(f"[sub2] selected (no TCP check): {len(selected2)}")

        await geo_lookup(session, list(dict.fromkeys(_extract(k, "host") for k in selected2)))

        selected2_with_lat = [(0, k) for k in selected2]
        write_output_2(selected2_with_lat)

        log.info(f"[sub2] done: {len(selected2)} keys")


if __name__ == "__main__":
    asyncio.run(main())
