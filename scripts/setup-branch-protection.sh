#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
# Configure branch protection rules for the koan repository
# using the GitHub CLI (gh).
#
# Prerequisites:
#   brew install gh        # or see https://cli.github.com
#   gh auth login          # authenticate with a PAT or OIDC
#
# Usage:
#   ./scripts/setup-branch-protection.sh [OWNER/REPO]
#
# Defaults to the repo determined by `gh repo view`.
# ──────────────────────────────────────────────────────────────
set -euo pipefail

REPO="${1:-$(gh repo view --json nameWithOwner -q .nameWithOwner)}"
BRANCH="main"

echo "🔒 Configuring branch protection for ${REPO}@${BRANCH}"
echo ""

# ── 1. Main branch protection ruleset (recommended over legacy API) ──
#    Rulesets are the newer GitHub mechanism and support bypass actors,
#    tag rules, and more granular controls.
#
#    We use the REST API directly because `gh ruleset create` is limited.

gh api \
  --method POST \
  -H "Accept: application/vnd.github+json" \
  "/repos/${REPO}/rulesets" \
  --input - <<'EOF'
{
  "name": "main-protection",
  "target": "branch",
  "enforcement": "active",
  "conditions": {
    "ref_name": {
      "include": ["refs/heads/main"],
      "exclude": []
    }
  },
  "bypass_actors": [
    {
      "actor_id": 5,
      "actor_type": "RepositoryRole",
      "bypass_mode": "always"
    }
  ],
  "rules": [
    {
      "type": "deletion"
    },
    {
      "type": "non_fast_forward"
    },
    {
      "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 1,
        "dismiss_stale_reviews_on_push": true,
        "require_code_owner_review": false,
        "require_last_push_approval": true,
        "required_review_thread_resolution": true
      }
    },
    {
      "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": true,
        "required_status_checks": [
          {
            "context": "lint"
          },
          {
            "context": "test (3.11)"
          },
          {
            "context": "test (3.12)"
          },
          {
            "context": "test (3.13)"
          },
          {
            "context": "typecheck"
          }
        ]
      }
    },
    {
      "type": "required_linear_history"
    }
  ]
}
EOF

echo ""
echo "✅ Branch ruleset 'main-protection' created for ${REPO}"
echo ""

# ── 2. Tag protection ruleset — only release workflow can push tags ──
gh api \
  --method POST \
  -H "Accept: application/vnd.github+json" \
  "/repos/${REPO}/rulesets" \
  --input - <<'EOF'
{
  "name": "release-tags",
  "target": "tag",
  "enforcement": "active",
  "conditions": {
    "ref_name": {
      "include": ["refs/tags/v*"],
      "exclude": []
    }
  },
  "bypass_actors": [
    {
      "actor_id": 5,
      "actor_type": "RepositoryRole",
      "bypass_mode": "always"
    }
  ],
  "rules": [
    {
      "type": "deletion"
    },
    {
      "type": "update"
    },
    {
      "type": "creation"
    }
  ]
}
EOF

echo "✅ Tag ruleset 'release-tags' created for ${REPO}"
echo ""
echo "Summary of protections applied:"
echo "  Branch '${BRANCH}':"
echo "    • Require pull request with 1 approval"
echo "    • Dismiss stale reviews on new pushes"
echo "    • Require last-push approval (no self-merge of final push)"
echo "    • Require conversation resolution"
echo "    • Require status checks: lint, test (3.11/3.12/3.13), typecheck"
echo "    • Status checks must be up-to-date (strict mode)"
echo "    • Require linear history (squash/rebase merges only)"
echo "    • Block branch deletion"
echo "    • Block force pushes"
echo ""
echo "  Tags 'v*':"
echo "    • Only repository admins can create/update/delete release tags"
echo ""
echo "To view rulesets:  gh api /repos/${REPO}/rulesets | jq"
