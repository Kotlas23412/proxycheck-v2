import os
import re
import json
import urllib.parse
import math
from pathlib import Path

# --- НАСТРОЙКИ ---
CONFIGS_DIR = 'configs'              # ← Исходные файлы
OUTPUT_DIR = 'vless_configs'         # ← Результаты в корне репозитория
TEMPLATE_FILE = 'tools/template.json' # ← Шаблон в tools

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
    print("🤖 ГЕНЕРАТОР VLESS ПРОКСИ-КОНФИГУРАЦИЙ")
    print("=" * 70)
    
    # Работаем относительно корня репозитория
    repo_root = Path.cwd()
    configs_dir = repo_root / CONFIGS_DIR
    output_dir = repo_root / OUTPUT_DIR
    template_file = repo_root / TEMPLATE_FILE
    
    print(f"📂 Корень репозитория: {repo_root}")
    print(f"📂 Папка с конфигами: {configs_dir}")
    print(f"📂 Папка для результатов: {output_dir}")
    
    all_links = []
    seen_hosts = set()

    for file_name in INPUT_FILES:
        file_path = configs_dir / file_name
        if not file_path.exists():
            print(f"⚠️  Файл не найден: {file_path}")
            continue
        
        print(f"📖 Читаю файл: {file_name}")
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or not line.startswith('vless://'):
                    continue
                try:
                    host = urllib.parse.urlsplit(line).hostname
                    if host and host not in seen_hosts:
                        seen_hosts.add(host)
                        all_links.append(line)
                except Exception:
                    continue
    
    print(f"\n✅ Найдено {len(all_links)} уникальных VLESS прокси")
    
    if not all_links:
        print("❌ Прокси не найдены. Проверьте файлы в папке configs/")
        return 1

    all_outbounds = []
    for i, link in enumerate(all_links):
        outbound_obj = parse_link_to_outbound(link, i)
        if outbound_obj:
            all_outbounds.append(outbound_obj)

    print(f"✅ Успешно обработано {len(all_outbounds)} прокси")

    # Создаём output папку
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Очищаем старые файлы
    for old_file in output_dir.glob('*.json'):
        old_file.unlink()
        print(f"🗑️  Удалён старый файл: {old_file.name}")
    
    try:
        with open(template_file, 'r', encoding='utf-8') as f:
            base_template = json.load(f)
    except FileNotFoundError:
        print(f"❌ Не найден файл {template_file}")
        return 1
    except json.JSONDecodeError:
        print(f"❌ Файл {template_file} содержит невалидный JSON")
        return 1

    standard_outbounds = [
        {"protocol": "freedom", "tag": "direct"},
        {"protocol": "blackhole", "tag": "block"}
    ]
    
    chunk_size = math.ceil(len(all_outbounds) / NUM_OUTPUT_FILES)
    
    print(f"\n📦 Создаю {NUM_OUTPUT_FILES} файлов по ~{chunk_size} прокси в каждом...\n")

    created_files = 0
    for i in range(NUM_OUTPUT_FILES):
        start_index = i * chunk_size
        end_index = start_index + chunk_size
        proxy_chunk = all_outbounds[start_index:end_index]

        if not proxy_chunk:
            break

        config = json.loads(json.dumps(base_template))
        proxy_tags = [p['tag'] for p in proxy_chunk]

        config['outbounds'] = proxy_chunk + standard_outbounds
        config['burstObservatory']['subjectSelector'] = proxy_tags
        config['routing']['balancers'][0]['selector'] = proxy_tags
        config['remarks'] = f"🚀 Группа {i+1}/{NUM_OUTPUT_FILES} ({len(proxy_chunk)} прокси)"

        output_filename = output_dir / f'vless_group_{i+1:02d}.json'
        with open(output_filename, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        
        print(f"  ✅ {output_filename.name} — {len(proxy_chunk)} прокси")
        created_files += 1

    print(f"\n{'=' * 70}")
    print(f"🎉 ГОТОВО! Создано {created_files} файлов в 
