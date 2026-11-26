#!/bin/bash
# Prints "code=true" or "code=false" for the changes job. Fails closed: false only
# when both API calls succeed, the file list is complete, and every changed path
# (a rename counts its old path too) is docs. Always exits 0: a failed job would
# skip lint and typecheck, and a skipped check satisfies a required status.
# Needs EVENT, REPO, PR in the environment, plus gh and jq on PATH.
code=true
if [ "$EVENT" = pull_request ]; then
  # one JSON array per file, so a newline in a name cannot split one path in two
  # docs/guides stays code: tests run the examples in those pages
  if names=$(gh api "repos/$REPO/pulls/$PR/files" --paginate --jq '.[] | [.filename, (.previous_filename // empty)] | @json') \
    && total=$(gh api "repos/$REPO/pulls/$PR" --jq .changed_files) \
    && [ "$total" -gt 0 ] && [ "$total" -lt 3000 ] \
    && [ "$(printf '%s\n' "$names" | grep -c .)" -eq "$total" ] \
    && printf '%s\n' "$names" | jq -e -s 'all(.[][]; test("^(?!.*\\.(py|pyi|ipynb)\\z)((docs/(?!guides/)|specs/|\\.specify/|\\.claude/).*|(?!SECURITY\\.md)[^/]+\\.md|mkdocs\\.yml|LICENSE)\\z"; "s"))' >/dev/null; then
    code=false
  fi
fi
echo "code=$code"
exit 0
