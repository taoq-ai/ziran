# Scanning Browser-Based Agents

This guide walks through scanning an AI agent that only exposes a web chat UI.

## Installation

```bash
pip install ziran[browser]
playwright install chromium
```

## Step 1: Create a Target Config

Create a YAML file describing how to interact with the chat UI:

```yaml
# target.yaml
url: https://chatbot.example.com/chat
protocol: browser

browser:
  input_selector: "textarea"
  submit_selector: "button[type='submit']"
  response_selector: ".assistant-message"
```

### Finding CSS Selectors

Open the chatbot in your browser and use DevTools (F12) to inspect:

1. **Input selector:** Right-click the text input, "Inspect", and note the `textarea` or `input` element
2. **Submit selector:** Right-click the send button and note its selector
3. **Response selector:** Right-click an assistant response bubble and note the common class

### Auto-Detection

If you omit `api_url_pattern`, ZIRAN sends a probe message and monitors which API endpoints the UI calls. For most standard chat UIs, auto-detection works well:

```yaml
url: https://chatbot.example.com/chat
protocol: browser
```

### Smart UI Discovery

ZIRAN automatically handles chatbot UIs that require interaction before the chat input appears:

- **Cookie banners:** Automatically dismissed (prefers "Reject" for privacy)
- **Chat launcher buttons:** Clicks "Start Chat", "Open Chat", and similar buttons
- **Hidden inputs:** Probes for `textarea`, `input`, `contenteditable`, and `[role='textbox']` elements
- **Submit buttons:** Discovers send/submit buttons near the input

This means a minimal config often works even for complex chat widgets:

```yaml
url: https://example.com/chatbot/
protocol: browser
```

To disable auto-discovery (e.g., if it interferes with a specific UI):

```yaml
browser:
  auto_discover: false
  input_selector: "#chat-input"
```

### Option / Quick-Reply Menus

Many chatbots present clickable options ("Track package", "Report issue") instead of accepting free text immediately. ZIRAN handles this automatically:

```yaml
browser:
  initial_options: auto          # auto (default), click_through, type_through, skip
  max_option_depth: 3            # how many menu levels to navigate
  option_selector: ""            # custom selector for option buttons (empty = auto-detect)
  prefer_options:                # option texts to prefer (tried first, case-insensitive)
    - "Vraag stellen"
    - "Ask a question"
```

Strategies:

- **`auto`** (default) — Looks for "Something else" / "Other" options first, then clicks the first option
- **`click_through`** — Clicks the first option at each level
- **`type_through`** — Ignores options and types directly (works if the bot accepts free text)
- **`skip`** — Does nothing about options

The `prefer_options` list is checked before all built-in patterns. Use it when you know which option leads to the LLM-powered free-text mode in a hybrid bot. Matches are case-insensitive substrings.

## Step 2: Run the Scan

```bash
# Standard scan
ziran scan --target target.yaml

# Essential coverage only (faster)
ziran scan --target target.yaml --coverage essential

# Force browser protocol
ziran scan --target target.yaml --protocol browser
```

## Step 3: Review Results

Reports are generated in the same formats as all ZIRAN scans:

```bash
open ziran_results/campaign_*_report.html
```

## Login Flows

For agents behind authentication:

```yaml
url: https://agent.example.com/chat
protocol: browser

browser:
  login_url: https://agent.example.com/login
  login_steps:
    - selector: "#email"
      action: fill
      value: "${AGENT_EMAIL}"
    - selector: "#password"
      action: fill
      value: "${AGENT_PASSWORD}"
    - selector: "button[type='submit']"
      action: click

  input_selector: "#chat-input"
  response_selector: ".bot-response"
```

Environment variables in `${VAR}` syntax are resolved at runtime.

## Timing Configuration

Adjust timeouts for slow-responding agents:

```yaml
browser:
  navigation_timeout: 30.0   # Page load timeout (seconds)
  response_timeout: 90.0     # Wait for agent response (seconds)
  settle_delay: 2.0          # Wait after last DOM change (seconds)
```

## Troubleshooting

### No response detected

- Increase `response_timeout` and `settle_delay`
- Check `response_selector` matches the actual DOM elements
- Run with `--verbose` to see detailed logs

### Wrong API endpoint detected

- Set `api_url_pattern` explicitly (e.g., `"**/api/chat/**"`)
- Set `response_json_path` to the correct field path

### Login fails

- Test selectors manually in the browser DevTools console
- Ensure environment variables are set for `${VAR}` references
- Check `login_url` is correct

### Auto-discovery clicks the wrong button

If ZIRAN clicks the wrong element during UI discovery, disable it:

```yaml
browser:
  auto_discover: false
  input_selector: "textarea"
  submit_selector: "button[type='submit']"
```

### Non-headless debugging

Set `headless: false` in the browser config to see the browser:

```yaml
browser:
  headless: false
```
