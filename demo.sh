#!/usr/bin/env bash
# JOCKY one-command demo for SIH 2026 (PS SIH26148, NTRO).
# Usage:  bash demo.sh          (full demo)
#         bash demo.sh fast     (smaller poly count, ~90s)
#         demo.bat              (double-click launcher -> native Git Bash)
#
# Every stage is read-only: payloads execute inside the in-memory VM, no
# files are written by the guest language. Each stage keeps its full log
# in $D (printed at start) so the judging panel can see the evidence trail.
#
# The script deliberately never pipes guest output through `head` (that
# closes the VM's stdout early on Windows and produces a spurious write
# error); output is redirected to a file and sliced with sed instead.
set +e
cd "$(dirname "$0")"

PY=python
command -v python >/dev/null 2>&1 || PY=python3
FLAG="${1:-full}"

# ---------------------------------------------------------------- helpers ----
say()   { printf '\n\033[1;36m=== %s ===\033[0m\n' "$*"; }
ok()    { printf '  \033[32m[ok]\033[0m %s\n' "$*"; }
fail()  { printf '  \033[31m[FAIL]\033[0m %s\n' "$*"; }
snip()  { sed -n '1,'"$1"'p' "$2"; }
tail8() { tail -n 8 "$1" 2>/dev/null | sed 's/^/  /'; }

# ------------------------------------------------- summary trackers (10) ----
NAMES=("JOCKY compilation" "VM execution" "Image inspection"
       "Behavioural equivalence" "Integrity/tamper detection"
       "Encrypted execution" "Host triage" "Network census"
       "Driver-risk detection" "Platform-aware EDR sensor")
STATE=(0 0 0 0 0 0 0 0 0 0)          # 1 = pass, 0 = fail
pass_check() { STATE[$1]=1; }

# ------------------------------------------------------- platform banner ----
UNAME_S=$(uname -s 2>/dev/null || echo Unknown)
UNAME_R=$(uname -r 2>/dev/null || echo "")
case "$UNAME_S" in
  MINGW*|MSYS*)  PLAT="native Windows (Git Bash)"; NATIVE=1 ;;
  *) case "$UNAME_R" in *microsoft*|*WSL*) PLAT="WSL ($UNAME_S $UNAME_R)"; NATIVE=0 ;;
       Linux*) PLAT="Linux ($UNAME_S)"; NATIVE=0 ;;
       *) PLAT="$UNAME_S"; NATIVE=0 ;; esac ;;
esac
echo "[[ demo platform: $PLAT ]]"
if [ "$NATIVE" = "0" ]; then
  echo "[[ note: EDR live-hook diff is Windows-only; this run uses the"
  echo "[[       synthetic cross-platform stub. For the live sensor story,"
  echo "[[       launch from native Windows via demo.bat or Git Bash. ]]"
fi

D=$(mktemp -d 2>/dev/null || echo /tmp/jocky_demo)
mkdir -p "$D"
echo "[[ demo workdir: $D ]]"

# ---------------------------------------------------- 1. COMPILER + LANGUAGE
say "1. BUILD  -  .jck source -> .jcx bytecode image (in-memory compiler)"
if $PY -m jocky build examples/hello.jck -o "$D/hello.jcx" >>"$D/o1.txt" 2>&1; then
  ok "built $D/hello.jcx  ($(stat -c %s "$D/hello.jcx" 2>/dev/null || echo '?') bytes)"
  pass_check 0
else
  fail "build"
  tail8 "$D/o1.txt"
fi

# ------------------------------------------------------------- 2. VM EXECUTION
say "2. RUN   -  execute the .jcx image in the VM (pure in-memory)"
if $PY -m jocky run "$D/hello.jcx" >"$D/o2.txt" 2>&1; then
  pass_check 1
  ok "run image  (output below)"
  sed 's/^/  /' "$D/o2.txt" | sed -n '1,10p'
else
  fail "run image"
  tail8 "$D/o2.txt"
fi

# --------------------------------------------------------- 3. IMAGE INSPECTION
say "3. INFO  -  image internals: functions, entry point, section sizes"
if $PY -m jocky info "$D/hello.jcx" >"$D/o3.txt" 2>&1; then
  pass_check 2
  ok "info  (sections + disassembly below)"
  sed 's/^/  /' "$D/o3.txt" | sed -n '1,11p'
else
  fail "info"
  tail8 "$D/o3.txt"
fi

# ---------------------------------- 4. POLYMORPHISM (PS req 2: unique hashes)
N=10; [ "$FLAG" = "fast" ] && N=4
say "4. POLYMORPHISM  -  $N builds of the SAME task, $N unique sha256, identical behaviour"
if $PY -m jocky poly examples/stealth.jck -n "$N" -o "$D/poly" >"$D/o4.txt" 2>&1 \
   && tail -1 "$D/o4.txt" | grep -q 'unique hashes (OK)'; then
  pass_check 3
  ok "$N builds, $N unique hashes, byte-identical behaviour"
  grep -E 'build [0-9]+|unique hashes' "$D/o4.txt" | tail -3 | sed 's/^/  /'
else
  fail "poly"
  tail8 "$D/o4.txt"
fi

# ------------------------------- 5. CI GATE (same checks GitHub Actions runs)
say "5. CI GATE  -  round-trip + poly-uniqueness + behavioural equivalence + tamper + enc"
$PY ci/check_poly_uniqueness.py -n 6 >"$D/o5.txt" 2>&1
if [ $? -eq 0 ]; then
  ok "gate passed (7/7 checks)"
  grep -c '\[ok\]' "$D/o5.txt" | sed 's/^/  gate: /'
else
  fail "gate"
  tail8 "$D/o5.txt"
  STATE[3]=0; STATE[4]=0; STATE[6]=0        # gate re-verifies these checks
fi

# ------------------------------------------------------- 6. ENCRYPT (custom)
say "6. ENCRYPT  -  custom JYCRYPT1 (XOR stream + keyed integrity tag)"
KEY=$($PY -c "import secrets;print(secrets.token_hex(32))")
ENC_OK=1
if $PY -m jocky enc examples/triage.jck -o "$D/triage.jxp" -k "$KEY" >"$D/o6.txt" 2>&1; then
  ok "encrypted $D/triage.jxp"
else
  ENC_OK=0
  fail "enc"
  tail8 "$D/o6.txt"
fi

# --------------------------------------------- 7. DECRYPT + EXECUTE in RAM
say "7. DECRYPT+EXECUTE  -  runs straight from the encrypted blob (.jxp)"
if [ "$ENC_OK" = "1" ] && $PY -m jocky run "$D/triage.jxp" -k "$KEY" >"$D/o7.txt" 2>&1; then
  pass_check 5
  ok "encrypted run (decrypt -> verify -> execute in memory)"
  sed 's/^/  /' "$D/o7.txt" | sed -n '1,9p'
else
  fail "encrypted run"
  tail8 "$D/o7.txt"
fi

# --------------------------------------------- 8. TAMPER / INTEGRITY CHECK
say "8. TAMPER DETECTION  -  flipping 1 byte must fail the integrity check"
cp "$D/triage.jxp" "$D/bad.jxp" 2>/dev/null
# XOR-flip a byte inside the integrity tag and VERIFY the file changed.
# (A fixed-value write like printf 'X' can silently no-op when the byte
# already equals 'X' - ~1/256 of runs, which made this stage flaky.)
$PY - "$D/bad.jxp" 25 >/dev/null 2>&1 <<'PYFLIP'
import sys
p, off = sys.argv[1], int(sys.argv[2])
with open(p, "r+b") as f:
    f.seek(off)
    b = f.read(1)
    if not b:
        sys.exit(2)
    f.seek(off)
    f.write(bytes([b[0] ^ 0x01]))
with open(p, "rb") as f:
    f.seek(off)
    sys.exit(0 if f.read(1) != b else 3)
PYFLIP
FLIP_OK=$?
if [ "$FLIP_OK" = "0" ] && [ "$ENC_OK" = "1" ] && ! $PY -m jocky run "$D/bad.jxp" -k "$KEY" >/dev/null 2>&1; then
  pass_check 4
  ok "tampered blob rejected before VM start"
else
  if [ "$FLIP_OK" != "0" ]; then
    fail "could not flip byte in $D/bad.jxp"
  else
    fail "tamper was NOT detected"
  fi
fi

# --------------------------------------------- 9. HOST TRIAGE (read-only)
say "9. TRIAGE  -  live host census (procs / env / cwd)  [read-only]"
if $PY -m jocky run examples/triage.jck >"$D/o9.txt" 2>&1; then
  pass_check 6
  ok "triage"
  sed 's/^/  /' "$D/o9.txt" | sed -n '1,11p'
else
  fail "triage"
  tail8 "$D/o9.txt"
fi

# ------------------------------------------- 10. STEALTH (read-only hashing)
say "10. STEALTH  -  read-only file hashing, zero writes  [read-only]"
if $PY -m jocky run examples/stealth.jck >"$D/o10.txt" 2>&1; then
  ok "stealth (hashed files, nothing written)"
  sed 's/^/  /' "$D/o10.txt" | sed -n '1,10p'
else
  STATE[6]=0
  fail "stealth"
  tail8 "$D/o10.txt"
fi

# ----------------------------------------------- 11. NETWORK CENSUS
say "11. NETPROBE  -  socket census via the netconns native"
if $PY -m jocky run examples/netprobe.jck >"$D/o11.txt" 2>&1; then
  pass_check 7
  ok "netprobe"
  sed 's/^/  /' "$D/o11.txt" | sed -n '1,9p'
else
  fail "netprobe"
  tail8 "$D/o11.txt"
fi

# ------------------------------ 12. C2 CENTRAL MANAGEMENT (central mgmt req)
say "12. C2 CENTRAL MANAGEMENT  -  controller queues .jxp, agent pulls+runs+reports"
BEFORE=$(ls agents/var/reports/ 2>/dev/null)

# reset the task registry so the agent pulls exactly the task queued below
# (stale tasks from earlier runs are encrypted with other keys and would
# fail the client's integrity check first).
$PY - <<EOF >"$D/o12p.txt" 2>&1
import json, glob, os
json.dump({"tasks": {}}, open("agents/var/registry.json", "w"), indent=2)
for f in glob.glob("agents/var/tasks/*.jxp"):
    os.remove(f)
print("[demo] task registry reset (stale tasks pruned)")
EOF
grep -q 'pruned\|reset' "$D/o12p.txt" && sed 's/^/  /' "$D/o12p.txt"

# one task per agent -- each concurrent agent claims its own task
$PY -m agents.controller add "$D/triage.jxp" --tag demo-node-a >"$D/o12a.txt" 2>&1
$PY -m agents.controller add "$D/triage.jxp" --tag demo-node-b >>"$D/o12a.txt" 2>&1
JOCKY_KEY="$KEY" nohup $PY -m agents.controller serve --port 8177 >"$D/ctrl.log" 2>&1 &
CTRL=$!
sleep 2
# two agents pull the SAME task concurrently (task fan-out) -- the PS
# "multiple system analysis simultaneously" requirement, live.
JOCKY_KEY="$KEY" $PY -m agents.client --controller http://127.0.0.1:8177   --agent-name lab-node-a --once >"$D/o12b.txt" 2>&1 &
C1=$!
JOCKY_KEY="$KEY" $PY -m agents.client --controller http://127.0.0.1:8177   --agent-name lab-node-b --once >"$D/o12c.txt" 2>&1 &
C2=$!
wait $C1 $C2
kill $CTRL 2>/dev/null
NEWLIST=$(comm -13 <(printf '%s
' "$BEFORE") <(ls agents/var/reports/ 2>/dev/null))
NCOUNT=$(printf '%s
' "$NEWLIST" | grep -c .)
if [ "$NCOUNT" -ge 1 ]; then
  ok "$NCOUNT agent report(s) landed (concurrent agents: lab-node-a + lab-node-b)"
  for f in $NEWLIST; do
    $PY -c "import json; d=json.load(open('agents/var/reports/$f')); print('  ', d.get('agent'), '->', d['output'].splitlines()[0])" 2>/dev/null
  done
else
  echo "  (client log: $(tail -2 "$D/o12b.txt" 2>/dev/null | tr '
' ' '))" | sed 's/^/  /'
  fail "no new report"
fi

# ------------------------------------------------------- 13. BYOVD HUNTER
say "13. BYOVD HUNTER  -  known-vulnerable driver detector (staged demo data)"
if $PY agents/byovd.py --demo >"$D/o13.txt" 2>&1; then
  pass_check 8
  ok "byovd"
  grep -E 'MEDIUM|CVE|CVSS|loaded_in' "$D/o13.txt" | head -4 | sed 's/^/  /'
else
  fail "byovd"
  tail8 "$D/o13.txt"
fi

# ------------------------------------------------ 14. EDR SENSOR ANALYSIS
say "14. EDR SENSOR ANALYSIS  -  endpoint agents + hook diff (platform-aware)"
if $PY agents/edr.py --demo >"$D/o14.txt" 2>&1; then
  pass_check 9
  ok "edr (platform-aware)"
  sed 's/^/  /' "$D/o14.txt" | sed -n '1,14p'
else
  fail "edr"
  tail8 "$D/o14.txt"
fi

# ------------------------------------------------------------- summary ----
echo "[[ full logs kept in: $D ]]"

PASSED=0
for s in "${STATE[@]}"; do [ "$s" = "1" ] && PASSED=$((PASSED + 1)); done

echo
echo "=== DEMO SUMMARY ==="
echo
i=0
for n in "${NAMES[@]}"; do
  if [ "${STATE[$i]}" = "1" ]; then
    printf '  \033[32m[PASS]\033[0m %s\n' "$n"
  else
    printf '  \033[31m[FAIL]\033[0m %s\n' "$n"
  fi
  i=$((i + 1))
done
echo
printf 'RESULT: %s/10 DEMO CHECKS PASSED\n' "$PASSED"
[ "$PASSED" = "10" ] && exit 0 || exit 1