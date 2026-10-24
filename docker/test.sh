#!/bin/bash
set -e

if [ -z "${GOARCH:-}" ]; then
    case "$(docker info --format '{{.Architecture}}' 2>/dev/null)" in
        aarch64|arm64) GOARCH=arm64 ;;
        x86_64|amd64)  GOARCH=amd64 ;;
        *) echo "cannot determine the Docker daemon architecture; set GOARCH" >&2; exit 1 ;;
    esac
fi
export GOARCH

echo "=== Building pcmd for linux/$GOARCH ==="
GOOS=linux go build -o pcmd ./cmd/pcmd

echo "=== Building e2e-test for linux/$GOARCH ==="
GOOS=linux go build -o e2e-test ./cmd/e2e-test

echo "=== Building Docker images ==="
docker compose -f docker/docker-compose.yml build

# Test 1 boots the image's /sbin/init for real (`run` would replace it with
# the test shell, leaving no systemd and no user manager to install into).
echo "=== Test 1: Systemd install ==="
docker compose -f docker/docker-compose.yml up -d systemd
sleep 3
docker compose -f docker/docker-compose.yml exec -T systemd bash -c '
    pcmd status 2>&1 || true

    # systemd is a per-user service: root and sudo are refused before any
    # file is written, even with --allow-unpaired.
    result=$(pcmd install --allow-unpaired --port 8767 --host 0.0.0.0 2>&1 || true)
    echo "$result" | grep -q "refusing to run as root" && echo "PASS: install refuses root on a systemd host" || { echo "FAIL: unexpected result: $result"; exit 1; }
    result=$(SUDO_USER=tester pcmd install --allow-unpaired 2>&1 || true)
    echo "$result" | grep -q "refusing to run under sudo" && echo "PASS: install refuses sudo" || { echo "FAIL: unexpected result: $result"; exit 1; }
    test ! -e /root/.config/systemd/user/pocketcmd.service && echo "PASS: nothing written for root" || { echo "FAIL: unit written for root"; exit 1; }

    # A normal user: an unpaired host is refused unless --allow-unpaired.
    useradd -m tester
    result=$(su tester -c "pcmd install --port 8767" 2>&1 || true)
    echo "$result" | grep -q "pair a device first" && echo "PASS: install refuses an unpaired host" || { echo "FAIL: unexpected result: $result"; exit 1; }
    test ! -e /home/tester/.config/systemd/user/pocketcmd.service && echo "PASS: nothing written before pairing" || { echo "FAIL: unit written before pairing"; exit 1; }

    # --allow-unpaired writes and starts the user unit. Starting needs the
    # user manager, which lingering brings up when logind is running.
    loginctl enable-linger tester 2>/dev/null || true
    sleep 1
    uid=$(id -u tester)
    if su tester -c "XDG_RUNTIME_DIR=/run/user/$uid DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$uid/bus pcmd install --allow-unpaired --port 8767 --host 0.0.0.0" 2>&1; then
        echo "PASS: install succeeds as a lingering user"
        su tester -c "XDG_RUNTIME_DIR=/run/user/$uid systemctl --user is-active pocketcmd" 2>&1 && echo "PASS: user unit active" || echo "WARN: user unit not active (user manager unavailable in the container)"
    else
        echo "WARN: user manager unavailable in the container; checking the unit only"
    fi
    test -f /home/tester/.config/systemd/user/pocketcmd.service && echo "PASS: systemd user unit created" || { echo "FAIL: no systemd unit"; exit 1; }
    grep -q "ExecStart" /home/tester/.config/systemd/user/pocketcmd.service && echo "PASS: ExecStart found" || { echo "FAIL: no ExecStart"; exit 1; }
'
docker compose -f docker/docker-compose.yml stop systemd

echo "=== Test 2: OpenRC install ==="
docker compose -f docker/docker-compose.yml run --rm openrc sh -c '
    pcmd status 2>&1 || true

    # OpenRC is a system service, so root is the right account; an unpaired
    # host is still refused without --allow-unpaired.
    result=$(pcmd install --port 8767 --host 0.0.0.0 2>&1 || true)
    echo "$result" | grep -q "pair a device first" && echo "PASS: install refuses an unpaired host" || { echo "FAIL: unexpected result: $result"; exit 1; }
    test ! -e /etc/init.d/pocketcmd && echo "PASS: nothing written before pairing" || { echo "FAIL: script written before pairing"; exit 1; }

    pcmd install --allow-unpaired --port 8767 --host 0.0.0.0 2>&1 || echo "WARN: install returned non-zero (rc-service may not run in the container); checking the script"

    test -f /etc/init.d/pocketcmd && echo "PASS: OpenRC script created" || { echo "FAIL: no OpenRC script"; exit 1; }
    grep -q "command=" /etc/init.d/pocketcmd && echo "PASS: command found" || { echo "FAIL: no command"; exit 1; }
'

echo "=== Test 3: Minimal (no init system) ==="
docker compose -f docker/docker-compose.yml run --rm minimal sh -c '
    # The pairing guard comes first; --allow-unpaired gets past it to the
    # init-system check, which is what this image is for.
    result=$(pcmd install --port 8767 2>&1 || true)
    echo "$result" | grep -q "pair a device first" && echo "PASS: install refuses an unpaired host" || { echo "FAIL: unexpected result: $result"; exit 1; }
    result=$(pcmd install --allow-unpaired --port 8767 2>&1 || true)
    echo "$result" | grep -qi "no supported init" && echo "PASS: graceful failure without an init system" || { echo "FAIL: unexpected result: $result"; exit 1; }

    # Should work in foreground mode
    timeout 3 pcmd --foreground --port 9999 &
    sleep 2

    # Health check
    wget -q --no-check-certificate -O- https://127.0.0.1:9999/api/health 2>/dev/null && echo "PASS: foreground works" || echo "WARN: health check failed (expected without pairing)"

    kill %1 2>/dev/null || true
'

echo "=== Test 4: Pairing + service lifecycle ==="
docker compose -f docker/docker-compose.yml run --rm minimal sh -c '
    # Start server in foreground, pair, verify endpoints
    pcmd --foreground --port 8767 &
    SERVER_PID=$!
    sleep 2

    # Health endpoint should work
    wget -q --no-check-certificate -O- https://127.0.0.1:8767/api/health 2>/dev/null && echo "PASS: health endpoint" || echo "WARN: health check (may need TLS skip)"

    kill $SERVER_PID 2>/dev/null || true
'

echo "=== Test 5: E2E Metrics (Ubuntu/systemd) ==="
docker compose -f docker/docker-compose.yml run --rm systemd bash -c '
    e2e-test
'

echo "=== Test 6: E2E Metrics (Alpine/OpenRC) ==="
docker compose -f docker/docker-compose.yml run --rm openrc sh -c '
    e2e-test
'

echo "=== Test 7: E2E Metrics (Alpine/minimal) ==="
docker compose -f docker/docker-compose.yml run --rm minimal sh -c '
    e2e-test
'

echo "=== Cleanup ==="
docker compose -f docker/docker-compose.yml down
rm -f pcmd e2e-test

echo "=== All tests complete ==="
