# Xray VLESS+WS+TLS Автоматический Установщик 🚀

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Простой и мощный Bash-скрипт для полностью автоматической установки и настройки VPN-сервера на базе **Xray** с использованием протокола **VLESS**, транспорта **WebSocket (WS)** и шифрования **TLS 1.3**. Скрипт ориентирован на обеспечение **низкой задержки (low latency)** для онлайн-игр, стабильного соединения и обхода интернет-блокировок средней сложности (DPI) путем маскировки трафика под стандартный HTTPS.

**Особенности:**

*   ✨ **Полностью Автоматический:** Запустил и забыл! Скрипт делает всё сам, от установки зависимостей до генерации конфигурации.
*   🚀 **Оптимизация для Скорости и Игр:**
    *   Использует VLESS (меньше оверхеда по сравнению с VMess).
    *   WebSocket (WS) для маскировки под веб-трафик.
    *   Автоматически включает **TCP BBR** (если поддерживается ядром) для улучшения пропускной способности.
    *   Базовые настройки Xray для стабильности.
*   🛡️ **Безопасность и Обход Блокировок:**
    *   **TLS 1.3** для шифрования трафика (используется самоподписанный сертификат).
    *   Маскировка под стандартный HTTPS-трафик для обхода DPI.
    *   Настройка защищенных DNS (DoH от Cloudflare/Google/Quad9) внутри Xray.
*   💻 **Широкая Поддержка ОС:**
    *   Ubuntu 20.04+
    *   Debian 10+
    *   CentOS 7+ / AlmaLinux / Rocky Linux
*   🔑 **Подключение по IP:** Не требует доменного имени. Идеально для быстрого развертывания на любом VPS.
*   ⚙️ **Простое Управление:** Интеграция с `systemd` для управления службой Xray (статус, перезапуск, логи).
*   📱 **Удобный Вывод:** Генерирует готовую **VLESS-ссылку** и **QR-код** для легкого импорта в клиенты.

---

##  Требуетчя для установки 

*   Чистый VPS (Виртуальный Частный Сервер).
*   Установленная поддерживаемая ОС (Ubuntu 20.04+, Debian 10+, CentOS 7+).
*   Доступ к серверу по SSH с правами `root` или пользователя с `sudo`.

---

## 🚀 Быстрый Старт

1.  **Подключитесь к вашему серверу по SSH.**

2.  **Скачайте скрипт:**
    ```bash
    wget -O install-vless.sh https://github.com/GoodyOG/Auto-intall-Xray-VLESS-WS-TLS/raw/refs/heads/main/install-vless.sh
    # ИЛИ если wget не установлен:
    # curl -o install-vless.sh https://github.com/GoodyOG/Auto-intall-Xray-VLESS-WS-TLS/raw/refs/heads/main/install-vless.sh
    ```

3.  **Сделайте скрипт исполняемым:**
    ```bash
    chmod +x install-vless.sh
    ```

4.  **Запустите скрипт с правами sudo:**
    ```bash
    sudo ./install-vless.sh
    ```

5.  **Дождитесь завершения!** Скрипт выполнит все необходимые шаги и выведет итоговую информацию.

---

## 🎉 После Установки

По завершении работы скрипт выведет в консоль:

*   **Параметры вашего VPN:** IP-адрес, порт, UUID, путь WS и т.д.
*   **Готовую VLESS-ссылку:** Вы можете скопировать её целиком.
*   **Информацию о QR-коде:** Файл `vless_qr.png` будет сохранен в домашней директории пользователя, запустившего `sudo` (обычно `/root/` если запуск от root, или `/home/username/` если через `sudo username`). Также будет показана команда для отображения QR-кода прямо в терминале (если он поддерживает UTF-8).

---

## 📱 Настройка Клиента (Очень Важно!)

1.  **Импортируйте конфигурацию:** Используйте VLESS-ссылку или QR-код в вашем VLESS-совместимом клиенте (например, v2rayNG, Nekoray, v2rayN, Shadowrocket, Stash, Streisand и др.).

2.  **⚠️ РАЗРЕШИТЕ НЕБЕЗОПАСНОЕ СОЕДИНЕНИЕ ⚠️**
    *   В настройках импортированного профиля (в разделе TLS/Security) **обязательно** найдите и включите опцию типа:
        *   `Allow Insecure` (Разрешить небезопасное)
        *   `skip certificate verification` (пропустить проверку сертификата)
        *   `tlsAllowInsecure=1` (или аналогичную)
    *   **Почему?** Скрипт использует *самоподписанный* TLS-сертификат, который не выдан доверенным центром сертификации. Эта опция говорит клиенту доверять этому конкретному сертификату. **Без этой опции подключение не будет установлено!**

3.  **Проверьте SNI / Host:** Убедитесь, что в настройках клиента в поле SNI (Server Name Indication) или Host указан **IP-адрес** вашего сервера. Скрипт автоматически подставляет его в генерируемую ссылку.

---

## 🔧 Управление Сервером Xray

Используйте стандартные команды `systemctl`:

*   **Проверить статус:** `sudo systemctl status xray`
*   **Перезапустить:** `sudo systemctl restart xray`
*   **Остановить:** `sudo systemctl stop xray`
*   **Запустить:** `sudo systemctl start xray`
*   **Включить автозапуск при загрузке:** `sudo systemctl enable xray`
*   **Выключить автозапуск:** `sudo systemctl disable xray`

**Просмотр логов:**

*   **Основные ошибки:** `sudo tail -f /var/log/xray/error.log`
*   **Логи доступа (если нужно включить в конфиге):** `sudo tail -f /var/log/xray/access.log`
*   **Полный лог службы:** `sudo journalctl -u xray -f --no-pager`

---

## ⚙️ Кастомизация

*   **Порт:** Вы можете изменить порт `VLESS_PORT` (по умолчанию `8443`) в начале скрипта *перед* его запуском. Не забудьте, что порт должен быть свободен.
*   **Оптимизация производительности:** Для тонкой настройки буферов и таймаутов можно отредактировать файл `/usr/local/etc/xray/config.json` *после* установки, добавив или изменив секцию `"policy"`. Требует перезапуска Xray (`sudo systemctl restart xray`) и тестирования.

---

## 🔍 Устранение Неполадок

*   **Служба Xray не запускается:**
    1.  Проверьте логи: `sudo journalctl -u xray -n 50 --no-pager`
    2.  Частая причина: **Порт занят**. Проверьте: `sudo ss -tlpn | grep <VLESS_PORT>` (замените `<VLESS_PORT>` на ваш порт, например 8443). Если порт занят, остановите другой процесс или измените порт в скрипте и запустите его заново.
    3.  Проверьте конфигурацию Xray: `sudo /usr/local/bin/xray -test -config /usr/local/etc/xray/config.json`
*   **Низкая скорость:**
    1.  Убедитесь, что **BBR включен** (скрипт пытается это сделать). Проверьте: `sysctl net.ipv4.tcp_congestion_control`. Должно быть `bbr`.
    2.  Проверьте скорость **на самом сервере**: `sudo apt install speedtest-cli -y && speedtest-cli` (или `yum`). Если она низкая, проблема у хостера.
    3.  Проверьте **маршрут и потери пакетов** от вашего компьютера до сервера с помощью `mtr` или `WinMTR`.
    4.  Проверьте **нагрузку на CPU** сервера во время использования VPN (`htop`). TLS-шифрование потребляет ресурсы CPU.
    5.  Попробуйте изменить `bufferSize` в `/usr/local/etc/xray/config.json` (см. Кастомизация).
*   **Не подключается клиент:**
    1.  Перепроверьте, что включена опция **"Allow Insecure"** в настройках клиента!
    2.  Убедитесь, что **SNI/Host** в клиенте равен IP-адресу сервера.
    3.  Проверьте, что **файрвол** на сервере разрешает входящие соединения на ваш `VLESS_PORT` (`sudo ufw status` или `sudo firewall-cmd --list-all`). Если UFW был неактивен, включите его: `sudo ufw enable`.

---

## 🔒 Замечание по Безопасности

Использование самоподписанного сертификата и опции `Allow Insecure` удобно для личного VPN без необходимости покупать домен. Однако, помните:

*   Клиент не проверяет подлинность сервера по цепочке доверия, а доверяет только тому сертификату, который сервер предоставил при первом подключении (или который зашит в конфигурацию).
*   Хотя трафик шифруется с помощью TLS 1.3, сам факт использования самоподписанного сертификата может быть индикатором для продвинутых систем DPI, особенно в сочетании с подключением по IP. Для максимальной маскировки обычно рекомендуют использовать валидный домен, CDN и более сложные конфигурации.

Этот скрипт предоставляет хороший баланс между простотой установки, скоростью и уровнем маскировки для обхода блокировок средней сложности.

---

## 📜 Лицензия

Этот проект лицензирован под лицензией MIT - см. файл `LICENSE` для подробностей (если вы его добавите).
