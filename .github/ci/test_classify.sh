#!/bin/bash
# Runs classify.sh against a stub gh. Each case: name, expected, mode, files JSON, changed_files.
# The stub applies the real --jq filter with jq, so rename and newline handling is exercised.
here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/bin"
cat > "$tmp/bin/gh" <<'EOF'
#!/bin/bash
# gh api <path> [--paginate] --jq <expr>
path=$2
expr=${@: -1}
case "$path" in
  */files)
    [ "$MODE" = apifail ] && exit 1
    jq -r "$expr" < "$FILES"
    [ "$MODE" = page2fail ] && exit 1
    exit 0 ;;
  *)
    [ "$MODE" = countfail ] && exit 1
    echo "$COUNT" ;;
esac
EOF
chmod +x "$tmp/bin/gh"

fail=0
check() { # name expected mode count files-json
  printf '%s' "$5" > "$tmp/files.json"
  got=$(PATH="$tmp/bin:$PATH" MODE=$3 COUNT=$4 FILES="$tmp/files.json" EVENT=pull_request REPO=o/r PR=1 bash "$here/classify.sh"; echo "rc=$?")
  want="code=$2
rc=0"
  if [ "$got" != "$want" ]; then echo "FAIL $1: got '$got', want '$want'"; fail=1; fi
}

check "docs only" false ok 2 '[{"filename":"docs/a.md"},{"filename":"README.md"}]'
check "code file" true ok 2 '[{"filename":"docs/a.md"},{"filename":"ziran/x.py"}]'
check "api error" true apifail 1 '[]'
check "failed page 2" true page2fail 2 '[{"filename":"docs/a.md"}]'
check "count error" true countfail 1 '[{"filename":"docs/a.md"}]'
check "truncated list" true ok 2 '[{"filename":"docs/a.md"}]'
check "over the cap" true ok 3000 '[{"filename":"docs/a.md"}]'
check "newline in a name" true ok 1 '[{"filename":"README.md\ndocs/evil.py"}]'
check "rename out of ziran" true ok 1 '[{"filename":"docs/m.md","previous_filename":"ziran/m.py"}]'
check "shipped prompt md" true ok 1 '[{"filename":"ziran/application/hybrid/prompts/trace_judge/v1.md"}]'
check "plugin skill md" true ok 1 '[{"filename":"plugins/ziran/skills/audit-agents/SKILL.md"}]'
check "tested guide" true ok 1 '[{"filename":"docs/guides/adapters.md"}]'
check "license lookalike" true ok 1 '[{"filename":"LICENSE.py"}]'
check "empty list" true ok 0 '[]'
check "empty list, one changed" true ok 1 '[]'
check "python in specs" true ok 1 '[{"filename":"specs/999-x/spike.py"}]'
check "python in .claude" true ok 1 '[{"filename":".claude/hooks/h.py"}]'
check "python in docs" true ok 1 '[{"filename":"docs/hooks.py"}]'
check "root SECURITY.md" true ok 1 '[{"filename":"SECURITY.md"}]'

[ "$fail" = 0 ] && echo "classify: all cases pass"
exit "$fail"
