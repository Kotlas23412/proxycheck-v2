import os
import re
import json
import urllib.parse
import math
from pathlib import Path

# --- НАСТРОЙКИ ---
CONFIGS_DIR = 'configs'
OUTPUT_DIR = 'output/vless_configs'  # ← Новый путь
TEMPLATE_FILE = 'scripts/template.json'

INPUT_FILES = [
    'top100_available',
    'ru_st'
]
NUM_OUTPUT_FILES = 10

def normalize_name(original_name, address, sni, index):
    flag = "🏴"
    country_name = "Сервер"
    
    upper_name = original_name.upper()
    explicit_regex = r'([\U0001F1E6-\U0001F1FF]{2})\s*([A-Za-zА-Яа-яЁё\-\s]+?)(?:\s*\[|\s*\||\s*#|\s*\*|$)'
    match = re.search(explicit_regex, original_name)
    
    if match:
        flag = match.group(1)
        raw_name = match.group(2).strip()
        if raw_name:
            mapping = {
                "FRANCE": "Франция", "GERMANY": "Германия", "NORWAY": "Норвегия",
                "THE NETHERLANDS": "Нидерланды", "NETHERLANDS": "Нидерланды",
                "RUSSIA": "Россия", "РОССИЯ": "Россия", "UNITED STATES": "США", "USA": "США",
                "UNITED KINGDOM": "Великобритания", "UK": "Великобритания",
                "FINLAND": "Финляндия", "SWEDEN": "Швеция", "POLAND": "Польша",
                "TURKEY": "Турция", "HUNGARY": "Венгрия", "ANDORRA": "Андорра"
            }
            country_name = mapping.get(raw_name.upper(), raw_name)
    
    if country_name == "Сервер" and sni:
        sni_lower = sni.lower()
        if any(x in sni_lower for x in ['.ru', '.su', 'yandex', 'vk.com', 'x5.ru']):
            flag, country_name = "🇷🇺", "Россия"
        elif sni_lower.endswith('.de'): flag, country_name = "🇩🇪", "Германия"
        elif sni_lower.endswith('.nl'): flag, country_name = "🇳🇱", "Нидерланды"
        elif sni_lower.endswith('.fi'): flag, country_name = "🇫🇮", "Финляндия"
        elif sni_lower.endswith('.us'): flag, country_name = "🇺🇸", "США"
        elif sni_lower.endswith(('.uk', '.co.uk')): flag, country_name = "🇬🇧", "Великобритания"
        elif sni_lower.endswith('.fr'): flag, country_name = "🇫🇷", "Франция"
        elif sni_lower.endswith('.se'): flag, country_name = "🇸🇪", "Швеция"
    
    return f"{flag} {country_name} #{index + 1}"

def parse_link_to_outbound(link, index):
    try:
        parsed = urllib.parse.urlsplit(link)
        if parsed.scheme.lower() != 'vless':
            return None
        
        params = dict(urllib.parse.parse_qsl(parsed.query))
        original_name = urllib.parse.unquote(parsed.fragment)
        address = parsed.hostname or ""
        port = parsed.port or 443
        uuid = parsed.username or ""
        sni = params.get('sni', '')

        tag = f"proxy-{index + 1}"
        remarks = normalize_name(original_name, address, sni, index)
        
        outbound = {
            "tag": tag,
            "remarks": remarks,
            "protocol": "vless",
            "settings": {},
            "streamSettings": {}
        }

        user = {
            "id": uuid,
            "encryption": params.get("encryption", "none")
        }
        if params.get("flow"):
            user["flow"] = params.get("flow")

        outbound["settings"]["vnext"] = [{"address": address, "port": port, "users": [user]}]

        network = params.get("type", "tcp")
        outbound["streamSettings"]["network"] = network

        if network == "ws":
            ws_settings = {}
            if "path" in params: ws_settings["path"] = params["path"]
            if "host" in params: ws_settings["headers"] = {"Host": params["host"]}
            outbound["streamSettings"]["wsSettings"] = ws_settings
        elif network == "grpc":
            grpc_settings = {}
            if "serviceName" in params: grpc_settings["serviceName"] = params["serviceName"]
            outbound["streamSettings"]["grpcSettings"] = grpc_settings

        sec = params.get("security", "")
        if sec in ["tls", "reality"]:
            outbound["streamSettings"]["security"] = sec
            sec_obj = {}
            if "sni" in params: sec_obj["serverName"] = params["sni"]
            if "fp" in params: sec_obj["fingerprint"] = params["fp"]
            
            if sec == "reality":
                if "pbk" in params: sec_obj["publicKey"] = params["pbk"]
                if "sid" in params: sec_obj["shortId"] = params["sid"]
                if "spx" in params: sec_obj["spiderX"] = params["spx"]
                outbound["streamSettings"]["realitySettings"] = sec_obj
            else:
                outbound["streamSettings"]["tlsSettings"] = sec_obj
        
        return outbound

    except Exception as e:
        print(f"⚠️  Ошибка парсинга: {str(e)[:50]}")
        return None

def main():
    print("=" * 70)
    print("🤖 ГЕНЕРАТОР VLESS ПРОКСИ-КОНФИГУРАЦИЙ (GitHub Actions Edition)")
    print("=" * 70)
    
    all_links = 
