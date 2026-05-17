# ambox (Linux)

Небольшое desktop-приложение в стиле Amnezia для подключения VPN по NekoBox/sing-box конфигам.

## Что умеет
- Импорт профилей из `sing-box` JSON или списка ссылок (`vmess://`, `vless://`, `trojan://`, `ss://`, `http://`, `https://`, `socks://`).
- Импорт профилей из буфера обмена.
- Выбор профиля в интерфейсе.
- Подключение/отключение через локальный `sing-box`.
- Показ статуса и логов в окне.
- Авто-замер latency и отслеживание timeout.
- Статистика трафика по каждому профилю (накопительно), с сохранением между запусками.
- Автопереключение на профиль с минимальной задержкой, если включена опция `Auto switch to lowest latency`.
- Гибкая маршрутизация: весь трафик, только выбранные домены, или весь трафик кроме выбранных доменов.
- Опция включения поддоменов для доменных правил.
- Режимы DNS: проксировать DNS, не проксировать DNS, или использовать `Custom DNS server`.
- Для `Custom DNS` поддерживаются `IP/домен[:port]`, `udp://...`, `tcp://...`; перед подключением сервер проверяется DNS-запросом.
- Флаг `-d` для debug-режима (подробные логи и traceback).

## Установка
```bash
cd /path/to/nekobox_gui_app
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt pyinstaller
```

## Важно про `sing-box`
Приложение запускает команду `sing-box run -c <config>`, поэтому `sing-box` должен быть установлен и доступен в `PATH`.

Пример для Ubuntu:
```bash
sudo apt install sing-box
```

Для TUN обычно нужны права `CAP_NET_ADMIN`:
```bash
sudo setcap cap_net_admin+ep "$(command -v sing-box)"
```

## Сборка одного файла (ELF)
```bash
cd /path/to/nekobox_gui_app
./build_linux.sh
```

После сборки бинарник будет тут:
```bash
/path/to/nekobox_gui_app/dist/ambox-linux
```

## Запуск
Обычный режим:
```bash
/path/to/nekobox_gui_app/dist/ambox-linux
```

Debug режим:
```bash
/path/to/nekobox_gui_app/dist/ambox-linux -d
```

Данные приложения сохраняются в `~/.ambox`:
```bash
~/.ambox/settings.ini       # настройки интерфейса, routing, DNS, статистика
~/.ambox/profiles.json      # импортированные VPN-профили
~/.ambox/active-config.json # текущий config для sing-box
~/.ambox/cache.db           # cache sing-box
~/.ambox/app.log            # лог приложения
~/.ambox/imports/           # локальная папка для ручного импорта конфигов
```

## Как использовать
1. Нажми `Import file`.
2. Выбери файл с конфигом.
3. Или используй `Paste from clipboard` / `Ctrl+V`.
4. Поддерживаются ссылки: `vless://`, `vmess://`, `trojan://`, `ss://`, `http://user:pass@host:port#Name`, `socks://user:pass@host:port#Name`.
5. Выбери режим `Routing`.
6. При режимах с доменами укажи домены построчно и при необходимости включи `Include subdomains`.
7. Для крупных сервисов (Google/YouTube/OpenAI и т.д.) обычно нужно добавить несколько связанных доменов/CDN, а не только один основной домен.
8. При необходимости включи `Auto switch to lowest latency`.
9. Выбери `DNS mode`: через прокси, напрямую, или `Custom DNS server`.
10. Для `Custom DNS server` укажи адрес (например, `1.1.1.1`, `dns.google`, `udp://1.1.1.1:53`).
11. Укажи `Timeout` в миллисекундах.
12. Нажми `Connect`.

Если видишь `sing-box not found`:
1. Установи `sing-box`, или
2. Нажми кнопку `Install sing-box` в приложении (используется `pkexec` + репозиторий SagerNet).

Если установка падает из-за `repository ... is not signed`:
1. Почини/отключи проблемный сторонний APT-репозиторий.
2. Повтори установку через кнопку `Install sing-box`.

## Ограничения текущей версии
- Не реализована поддержка подписок NekoBox по URL (в этой версии только локальные файлы).
- Латентность измеряется TCP-подключением к endpoint профиля (не полноценный throughput-тест).
