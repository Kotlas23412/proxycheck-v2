# VPN-проверка в GitHub Actions

Да, в GitHub можно поднять VPN **внутри workflow job** и выполнить проверку трафика через него.

Ограничения:
- VPN действует только в пределах запущенной job (временная VM).
- Это не «постоянный VPN» для вашего телефона/ПК.
- Для подключения нужны секреты с конфигом VPN.

## Что добавлено

Workflow: `.github/workflows/vpn-connectivity-check.yml`

Ручной запуск через **Actions → VPN connectivity check → Run workflow**.

Параметры запуска:
- `vpn_type`: `openvpn` или `wireguard`
- `test_url`: URL для проверки через VPN (по умолчанию `https://www.gstatic.com/generate_204`)

## Секреты

### OpenVPN
- `OVPN_CONFIG_B64` — base64 от `.ovpn` файла
- `OVPN_AUTH_B64` — optional, base64 от файла с логином/паролем (`username` на первой строке, `password` на второй)

### WireGuard
- `WG_CONFIG_B64` — base64 от `wg0.conf`

## Как подготовить base64 локально

Linux/macOS:

```bash
base64 -w 0 client.ovpn
base64 -w 0 auth.txt
base64 -w 0 wg0.conf
```

macOS (BSD base64 без `-w`):

```bash
base64 < client.ovpn | tr -d '\n'
```

## Что делает workflow

1. Показывает внешний IP до VPN.
2. Устанавливает OpenVPN/WireGuard tools.
3. Поднимает выбранный VPN.
4. Проверяет внешний IP после подключения.
5. Проверяет `test_url` через `curl`.
6. Запускает `python -m lib.vless_checker` с минимальными настройками, чтобы прогон шел через активный VPN.

## Важно

Если ваш OpenVPN конфиг требует дополнительные сертификаты/inline-ключи, они должны быть включены прямо в `.ovpn` или доступны внутри конфига.
