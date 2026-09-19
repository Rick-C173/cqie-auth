#!/bin/bash
cd /home/rick/cqie_auth
TMP=$(mktemp -d)
APORT=33399
cat > "$TMP/a6_override.h" <<EOH
#define PORTAL_URL      "http://127.0.0.1:$APORT/eportal"
#define PROBE_URL       "http://127.0.0.1:$APORT/probe"
#define PROBE_204_LIST  "http://127.0.0.1:1/generate_204"
#define STATE_DIR       "$TMP/state"
#define USER_ID         "testuser"
#define PASSWORD        "test-pass-123"
EOH
cc -O2 -std=c99 -Iinclude -include "$TMP/a6_override.h" -o "$TMP/cqie" src/*.c || exit 1
python3 tests/mock_ac.py $APORT test-pass-123 "$TMP/log.json" "$TMP/key.txt" >/dev/null 2>&1 &
sleep 1
printf 'user=testuser\npassword=test-pass-123\nservice=\n# keep\n' > "$TMP/af.conf"
CQIE_DEBUG=1 "$TMP/cqie" login --config "$TMP/af.conf" --state-dir "$TMP/state" 2>&1 | grep -E '运营商|exit|写回'; echo "exit=$?"
echo '--- af.conf ---'
cat "$TMP/af.conf"
kill %1 2>/dev/null
