# Contract: Slack + GitHub HTTP request shapes

These are the exact request shapes integration tests (respx) assert against.

## SlackWebhookSink

**Request**: `POST {webhook_url}` (URL from `!env`), `Content-Type: application/json`.

**Body** (Block Kit + text fallback):
```json
{
  "text": "<severity emoji> [<KIND>] <finding.summary>",
  "blocks": [
    { "type": "header", "text": { "type": "plain_text", "text": "<emoji> <finding.title>" } },
    { "type": "section", "fields": [
        { "type": "mrkdwn", "text": "*<field key>:*\n<field value>" }
    ] },
    { "type": "context", "elements": [
        { "type": "mrkdwn", "text": "<label>: <url>" }
    ] }
  ]
}
```
**Success**: HTTP 200 with body `ok` → `status="sent"`. Non-2xx → `status="failed"`.

Severity → emoji: critical `:rotating_light:`, high `:red_circle:`, medium `:large_orange_diamond:`, low `:white_circle:`.

## GitHubIssueSink

Token from `!env`/`GITHUB_TOKEN`; headers `Authorization: Bearer <token>`, `Accept: application/vnd.github+json`, `X-GitHub-Api-Version: 2022-11-28`.

**Step 1 — dedup search**:
`GET https://api.github.com/search/issues?q=repo:{repo}+in:body+%22ziran-fingerprint%3A+{fp}%22+is:issue`
- `total_count > 0` → return `DeliveryResult(status="deduped", detail=<items[0].html_url>)`. No creation.

**Step 2 — create (only if not found)**:
`POST https://api.github.com/repos/{repo}/issues`
```json
{
  "title": "<KIND>: <finding.title>",
  "body": "<rendered markdown>\n\n<!-- ziran-fingerprint: <fp> -->",
  "labels": ["<configured labels>"],
  "assignees": ["<configured assignees>"]
}
```
- 201 → `status="sent"`, `detail=<html_url>`.
- 401/403 (bad/missing token) → `status="failed"`, detail names the auth problem.
- other non-2xx → `status="failed"`.

**Body markdown** includes: finding fields as a list, each `AlertLink` as a markdown link, severity, and `remediation` (if present) under a "Suggested remediation" heading.

**Idempotency test**: first run → search returns 0 → POST observed once → `sent`; second run on same finding → search returns 1 → no POST → `deduped`. (SC-002.)
