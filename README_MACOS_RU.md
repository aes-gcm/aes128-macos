# AES128 VPN для macOS

Исходники клиента [aes.cx](https://aes.cx) для Apple Silicon и macOS 13+. Версия 1.0.3 с исправлениями после проверки исходников. Сборка предназначена для разработки и тестирования; нотарифицированного публичного установщика в репозитории нет.

## Возможности и ограничения

Поддерживаются VLESS XHTTP, XTLS Vision, пользовательские VLESS-ссылки и раздельная маршрутизация по доменам. GUI работает от обычного пользователя, системная служба — от root. Ключ шифрования сессии хранится в Keychain, файлы настроек — в `~/Library/Application Support/AES128 VPN` с ограниченными правами.

Служба проверяет пользователя Unix-соединения при подключении и при каждом RPC. Ядра проверяются по встроенным хешам и копируются в защищённый каталог. Перед изменением DNS сохраняется журнал восстановления. При отключении или сбое служба останавливает ядра и восстанавливает сеть; неудачное восстановление повторяется.

Kill switch и Hysteria2 недоступны. При сбое возвращается обычное подключение. Intel/universal не поддерживаются скриптами сборки. Полный IPv6/DNS leak audit, физический сон и пробуждение, смена Wi-Fi, перезагрузка, Tor и Reality требуют отдельных испытаний.

## Сборка

Нужны Go 1.26.8+, Node.js 22.12+, Python 3 и Xcode Command Line Tools. Сохраняйте взаимное расположение `aes128`, `backend` и `proto`.

```sh
python3 scripts/fetch-macos-cores.py ./cores
export AES128_CORES="$PWD/cores"
export AES128_OUTPUT="$PWD/build-macos"
export AES128_SIGN_IDENTITY='Apple Development: YOUR IDENTITY'
./scripts/build-macos.sh
AES128_APP="$AES128_OUTPUT/AES128 VPN.app" ./scripts/build-macos-installer.sh
```

Без identity приложение получает ad-hoc подпись для проверки сборки. Такой режим не подтверждает работоспособность регистрации helper и Keychain. Для проверки установки используйте свой Apple signing identity. Для подписи `.pkg` задайте `AES128_INSTALLER_IDENTITY`. Без него установщик остаётся неподписанным. Developer ID и notarization для публичного распространения выполняются отдельно.

## Проверки

```sh
(cd aes128/frontend && npm ci --ignore-scripts && npm run build)
(cd backend && go test -race ./... && go vet ./...)
(cd aes128 && MACOSX_DEPLOYMENT_TARGET=13.0 go test -race -ldflags=-extldflags=-mmacosx-version-min=13.0 ./... && go vet ./...)
(cd proto/vpnpb && go test ./... && go vet ./...)
python3 packaging/macos/tests/test_scripts.py
```

Для проверки конфигураций закреплёнными ядрами передайте backend-тестам `AES128_CORE_DIR=/absolute/path/to/cores`. Обычные тесты не подключают VPN; команды установщика подменяются тестовыми реализациями.

Тесты установленной службы включаются через `AES128_TEST_INSTALLED=1` или `AES128_TEST_PACKAGE_HELPER=1`; Keychain — через `AES128_TEST_KEYCHAIN=1`. Для Keychain тестовый бинарник должен иметь ту же signing identity и identifier, что приложение.

Живые тесты требуют отдельного временного аккаунта с префиксом `aes128qa_`. Переменная `AES128_LIVE_QA_FILE` указывает на локальный JSON с `Username`, `Password`, `UUID`, `Host`, `XHTTPPort`, `XTLSPort`. Не добавляйте этот файл в Git. Сетевые тесты включаются через `AES128_TEST_MACOS_TUNNEL=1` и меняют маршруты/DNS: запускайте их только на отдельном тестовом Mac и согласованном QA-сервере. Старого стенда в исходниках нет.

## Установка и удаление

`.pkg` размещает приложение в `/Applications`, LaunchDaemon в `/Library/LaunchDaemons` и служебные бинарники в `/Library/PrivilegedHelperTools/com.aes128.vpn`. Закройте старое приложение перед обновлением. Обновление сохраняет настройки и Keychain. При ручной установке `.app` helper регистрируется через SMAppService и может потребовать разрешения в настройках macOS.

Скрытие окна оставляет VPN активным; Cmd+Q/Exit отключает его. Для удаления установленной через `.pkg` службы закройте клиент и выполните:

```sh
sudo launchctl bootout system/com.aes128.vpn.helper
pgrep -x aes128-helper
```

Дождитесь завершения процесса: служба восстанавливает DNS и маршруты. Когда `pgrep` перестанет показывать PID:

```sh
sudo rm -f /Library/LaunchDaemons/com.aes128.vpn.helper.plist
sudo rm -rf /Library/PrivilegedHelperTools/com.aes128.vpn
sudo pkgutil --forget com.aes128.vpn.pkg
```

Затем удалите приложение из «Программы». Эти команды сохраняют настройки пользователя, Keychain и журнал восстановления DNS. Не удаляйте журнал, если восстановление сети не завершилось.

Сведения о внешних компонентах и лицензиях — в [README](README.md#external-components-and-licensing).
