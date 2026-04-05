# RST Debug Monitor

Это хостовый монитор входящих TCP `RST` для `443/tcp`.
Он нужен для быстрой диагностики на Debian-подобных VPS, когда нужно понять, выглядят ли входящие `RST` как нормальное закрытие соединения или как что-то подозрительное.

## Что Делает

- Следит за входящим TCP-трафиком на одном интерфейсе, по умолчанию `eth0`
- Анализирует только один целевой порт, по умолчанию `443`
- Запоминает недавние не-`RST` пакеты для каждого замеченного клиентского потока
- Читает `/proc/net/nf_conntrack`, чтобы понять, знает ли ядро это соединение
- Пишет короткие строки с вердиктом в лог
- Не добавляет правила firewall, не блокирует IP и не меняет маршрутизацию

## Метки Вердикта

- `[normal  ]`: похоже на нормальное закрытие соединения
- `[norm-fin]`: похоже на нормальное закрытие после `FIN`
- `[has-conn]`: ядро знает соединение, но локальных наблюдений мало
- `[unknown ]`: данных недостаточно, чтобы сделать уверенный вывод
- `[susp-ttl]`: `RST TTL` сильно отличается от недавних пакетов того же потока
- `[no-flow?]`: нет недавнего контекста потока и нет совпадения в `conntrack`

## Требования

- Linux-хост с `root`-доступом
- `python3`
- `tcpdump`
- доступный `/proc/net/nf_conntrack`

## Установка

```bash
apt-get update
apt-get install -y python3 tcpdump
git clone git@github.com:denash-git/Monitor-RST.git
cd Monitor-RST
bash install.sh
```

## Просмотр

Обычный лог:

```bash
tail -f /var/log/transithub-rst-debug/rst443.log
```

Цветной просмотр:

```bash
/usr/local/bin/transithub-rst-debug-watch-color
```

## Настройка

Редактировать:

```bash
/etc/default/transithub-rst-debug
```

Значения по умолчанию:

```bash
RST_DEBUG_IFACE=eth0
RST_DEBUG_PORT=443
RST_DEBUG_LOG=/var/log/transithub-rst-debug/rst443.log
```

После изменения перезапустить:

```bash
systemctl restart transithub-rst-debug.service
```

## Удаление

```bash
cd Monitor-RST
bash uninstall.sh
```

Скрипт удаляет сервис и бинарники, но оставляет:

- `/etc/default/transithub-rst-debug`
- `/var/log/transithub-rst-debug`

## Примечания

- Монитор универсальный и не привязан к Docker или внутренностям TransitHub.
- Лучше всего работает на хосте, который сам принимает или форвардит публичный `443/tcp`.
- По дизайну он пассивный и ничего не блокирует.
