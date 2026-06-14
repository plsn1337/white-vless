import base64
import json
import random
import re
import urllib.parse
import uuid
from curl_cffi import requests

url = "https://sub.nosok-top.com/Ryk4bMACd4JE1MF_"

windows_versions = [
    ("Windows 11 Pro", "24H2", "10.0.26100"),
    ("Windows 11 Home", "23H2", "10.0.22631"),
    ("Windows 10 Pro", "22H2", "10.0.19045"),
    ("Windows 10 Enterprise", "22H2", "10.0.19045")
]

win_name, win_ver, win_build = random.choice(windows_versions)
random_hwid = str(uuid.uuid4()).upper()

headers = {
    "user-agent": "v2raytun/windows",
    "x-device-model": f"PC | {win_name}",
    "x-ver-os": f"{win_name} | {win_ver} | {win_build}",
    "accept-encoding": "gzip",
    "x-device-os": "Windows",
    "x-app-version": "3.8.12",
    "x-hwid": random_hwid
}

try:
    print(f"[*] HWID: {random_hwid} | OS: {win_name} {win_ver}")
    print("[*] Отправка запроса...")
    
    response = requests.get(url, headers=headers, impersonate="chrome", timeout=15)
    raw_data = response.text.strip()
    
    print("[+] Ответ получен. Обработка данных...")

    if "App not supported" in raw_data and "0.0.0.0" in raw_data:
        print("[-] Ошибка: Сервер вернул заглушку блокировки.")
        
    elif raw_data.startswith("{") or raw_data.startswith("["):
        config = json.loads(raw_data)
        
        def find_vless(data_obj):
            links = []
            if isinstance(data_obj, dict):
                if data_obj.get("type") == "vless":
                    server = data_obj.get("server")
                    port = data_obj.get("port")
                    uuid_val = data_obj.get("uuid")
                    name = data_obj.get("tag", "VLESS_Server")
                    if server and port and uuid_val:
                        links.append(f"vless://{uuid_val}@{server}:{port}?security=tls&type=tcp#{urllib.parse.quote(name)}")
                for v in data_obj.values():
                    links.extend(find_vless(v))
            elif isinstance(data_obj, list):
                for item in data_obj:
                    links.extend(find_vless(item))
            return links

        vless_links = find_vless(config)
        if vless_links:
            print(f"[+] Найдено VLESS серверов: {len(vless_links)}")
            with open("vless_links.txt", "w", encoding="utf-8") as f:
                f.write("\n".join(vless_links))
            print("[+] Результат сохранен в vless_links.txt")
        else:
            print("[-] В JSON-конфиге не найдено VLESS секций.")

    else:
        try:
            missing_padding = len(raw_data) % 4
            if missing_padding:
                raw_data += '=' * (4 - missing_padding)
                
            decoded_text = base64.b64decode(raw_data).decode("utf-8")
            
            if "vless://" in decoded_text and "0.0.0.0" not in decoded_text:
                print(f"[+] Успешно извлечено Base64 подписки!")
                with open("vless_links.txt", "w", encoding="utf-8") as f:
                    f.write(decoded_text)
                print("[+] Результат сохранен в vless_links.txt")
            else:
                print("[-] Декодировано, но внутри обнаружена ошибка или пустой текст.")
        except:
            print("[!] Ошибка парсинга Base64. Возможно, пришел YAML.")
            proxies = re.findall(r'server:\s*([^\s]+)', raw_data)
            print(f"[-] Найденные сервера текстом: {proxies}")

except Exception as e:
    print(f"[!] Критическая ошибка: {e}")
