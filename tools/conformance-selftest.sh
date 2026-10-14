#!/usr/bin/env bash
# Exercises tools/conformance.sh in each state and checks the line it
# prints and its exit status (WP-13 tests): the suite absent (skipped,
# exit 0; failed, exit 1, when CONFORMANCE_REQUIRE_SUITE=1), present without an entry point (failed, exit 1), present and
# passing (passed, exit 0, CISP_BASE_URL and the report directory handed
# over), present and failing (failed, the suite's exit status). The
# suites are fakes in a scratch LAB_DIR, run against a given base URL,
# so no stack is started.
set -euo pipefail
cd "$(dirname "$0")/.."

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
fails=0

# expect <name> <want exit> <want substring> -- env assignments...
expect() {
  local name="$1" want_rc="$2" want="$3"; shift 3
  local out rc=0
  out="$(env -u GITHUB_STEP_SUMMARY "$@" tools/conformance.sh 2>&1)" || rc=$?
  if [ "$rc" -ne "$want_rc" ] || [[ "$out" != *"$want"* ]]; then
    echo "FAIL $name: exit $rc (want $want_rc), output:"; echo "$out" | sed 's/^/  /'
    fails=$((fails + 1))
  else
    echo "ok   $name: exit $rc: $(echo "$out" | tail -n 1)"
  fi
}

expect "absent" 0 "lab conformance suite not present at $scratch/none/conformance/cisp: skipped" \
  LAB_DIR="$scratch/none"
expect "absent but required" 1 "lab conformance suite not present at $scratch/none/conformance/cisp: failed (CONFORMANCE_REQUIRE_SUITE=1)" \
  LAB_DIR="$scratch/none" CONFORMANCE_REQUIRE_SUITE=1

mkdir -p "$scratch/norun/conformance/cisp"
expect "present without run" 1 "has no executable run: failed" LAB_DIR="$scratch/norun"

mkdir -p "$scratch/pass/conformance/cisp"
cat > "$scratch/pass/conformance/cisp/run" <<'EOF'
#!/usr/bin/env bash
set -eu
[ "$CISP_BASE_URL" = "http://cisp.selftest.invalid" ] || { echo "CISP_BASE_URL=$CISP_BASE_URL"; exit 3; }
echo "suite ran against $CISP_BASE_URL" > "$CONFORMANCE_REPORT/report.txt"
EOF
chmod +x "$scratch/pass/conformance/cisp/run"
expect "present and passing" 0 "against http://cisp.selftest.invalid: passed" \
  LAB_DIR="$scratch/pass" CISP_CONFORMANCE_BASE_URL=http://cisp.selftest.invalid CONFORMANCE_REPORT="$scratch/report"
if [ "$(cat "$scratch/report/report.txt" 2>/dev/null)" != "suite ran against http://cisp.selftest.invalid" ]; then
  echo "FAIL present and passing: the suite's report was not written"; fails=$((fails + 1))
fi

mkdir -p "$scratch/fail/conformance/cisp"
printf '#!/usr/bin/env bash\necho "1 conformance case failed"\nexit 7\n' > "$scratch/fail/conformance/cisp/run"
chmod +x "$scratch/fail/conformance/cisp/run"
expect "present and failing" 7 "failed (exit 7)" \
  LAB_DIR="$scratch/fail" CISP_CONFORMANCE_BASE_URL=http://cisp.selftest.invalid CONFORMANCE_REPORT="$scratch/report2"

# The chaos path: with no base URL set, conformance.sh runs go test in
# test/e2e with LAB_CONFORMANCE_SUITE. A fake go (GO=) plays that test:
# from its working directory it must find the suite's run through the
# variable, which a relative LAB_DIR broke.
rel="$(mktemp -d -p "$PWD" .conformance-selftest.XXXXXX)"
trap 'rm -rf "$scratch" "$rel"' EXIT
mkdir -p "$rel/lab/conformance/cisp"
printf '#!/usr/bin/env bash\nexit 0\n' > "$rel/lab/conformance/cisp/run"
chmod +x "$rel/lab/conformance/cisp/run"
cat > "$scratch/fakego" <<'EOF'
#!/usr/bin/env bash
case "$LAB_CONFORMANCE_SUITE" in /* | [A-Za-z]:*) ;; *) echo "LAB_CONFORMANCE_SUITE is not absolute: $LAB_CONFORMANCE_SUITE"; exit 4 ;; esac
[ "$(basename "$PWD")" = e2e ] || { echo "not run in test/e2e: $PWD"; exit 5; }
[ -x "$LAB_CONFORMANCE_SUITE/run" ] || { echo "fork/exec $LAB_CONFORMANCE_SUITE/run: no such file"; exit 6; }
EOF
chmod +x "$scratch/fakego"
expect "chaos path with a relative LAB_DIR" 0 "passed, report in $scratch/report3" \
  GO="$scratch/fakego" LAB_DIR="$(basename "$rel")/lab" CONFORMANCE_REPORT="$scratch/report3"

if [ "$fails" -ne 0 ]; then echo "conformance self-test: $fails failed"; exit 1; fi
echo "conformance self-test: 7 checks passed"
