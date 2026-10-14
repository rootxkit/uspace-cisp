#!/usr/bin/env bash
# make conformance (docs/PLAN.md section 10.6): the lab's ED-318
# publication tests against a running CISP.
#
# The suite is uspace-lab's conformance/cisp/ (L-M4). Until it exists the
# run says so and exits 0, never silently: the line below goes to stdout
# and to the CI step summary. When it exists, its entry point is the
# executable conformance/cisp/run (docs/PLAN.md section 15 Q47), called
# with
#
#   CISP_BASE_URL       the CISP under test
#   CONFORMANCE_ENV     a file of KEY=VALUE lines with the tokens, keys and
#                       identities the stack under test accepts (may be empty)
#   CONFORMANCE_REPORT  a directory for its report (CI uploads it)
#
# and its exit status is this script's. The CISP under test is
# CISP_CONFORMANCE_BASE_URL when set (with CISP_CONFORMANCE_ENV); unset,
# the chaos stack of test/e2e is started from this checkout's images and
# the suite runs against it (TestLabConformance), then the stack stops.
# CONFORMANCE_REQUIRE_SUITE=1 makes an absent suite a failure.
set -euo pipefail
cd "$(dirname "$0")/.."

GO="${GO:-go}"
LAB_DIR="${LAB_DIR:-../uspace-lab}"
suite="$LAB_DIR/conformance/cisp"
report="${CONFORMANCE_REPORT:-$PWD/conformance-report}"

say() {
  echo "$1"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then echo "$1" >> "$GITHUB_STEP_SUMMARY"; fi
}

if [ ! -d "$suite" ]; then
  # CI sets CONFORMANCE_REQUIRE_SUITE=1 once the pinned lab commit has
  # the suite: a skip there would be a green job that tested nothing.
  if [ "${CONFORMANCE_REQUIRE_SUITE:-}" = 1 ]; then
    say "lab conformance suite not present at $suite: failed (CONFORMANCE_REQUIRE_SUITE=1)"
    exit 1
  fi
  say "lab conformance suite not present at $suite: skipped"
  exit 0
fi
if [ ! -x "$suite/run" ]; then
  say "lab conformance suite at $suite has no executable run: failed"
  exit 1
fi

mkdir -p "$report"
if [ -z "${CISP_CONFORMANCE_BASE_URL:-}" ]; then
  say "lab conformance suite at $suite: starting the chaos stack from this checkout"
  # go test below runs in test/e2e, where a relative suite path (from a
  # relative LAB_DIR) no longer resolves.
  suite="$(cd "$suite" && pwd)"
  export LAB_CONFORMANCE_SUITE="$suite" CONFORMANCE_REPORT="$report"
  rc=0
  (cd test/e2e && "$GO" test -tags chaos -count=1 -v -timeout 30m -run '^TestLabConformance$' .) || rc=$?
  if [ "$rc" -ne 0 ]; then say "lab conformance suite at $suite: failed (exit $rc), report in $report"; exit "$rc"; fi
  say "lab conformance suite at $suite: passed, report in $report"
  exit 0
fi

rc=0
CISP_BASE_URL="$CISP_CONFORMANCE_BASE_URL" CONFORMANCE_ENV="${CISP_CONFORMANCE_ENV:-}" \
  CONFORMANCE_REPORT="$report" "$suite/run" || rc=$?
if [ "$rc" -ne 0 ]; then
  say "lab conformance suite at $suite against $CISP_CONFORMANCE_BASE_URL: failed (exit $rc), report in $report"
  exit "$rc"
fi
say "lab conformance suite at $suite against $CISP_CONFORMANCE_BASE_URL: passed, report in $report"
