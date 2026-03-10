# Example 20: Browser Agent Scan

Scan an AI agent through its web chat UI using a headless browser (Playwright).

This is useful when the agent only exposes a chat interface with no API.
ZIRAN uses network interception to capture the underlying API calls,
or falls back to DOM extraction when no API is detected.

## Prerequisites

```bash
pip install ziran[browser]
playwright install chromium
```

## Target Configuration

### Basic (with explicit API pattern)

```yaml
# target-browser.yaml
url: https://chatbot.example.com/chat
protocol: browser

browser:
  input_selector: "textarea[placeholder*='message']"
  submit_selector: "button[aria-label='Send']"
  api_url_pattern: "**/api/chat/completions"
  response_json_path: "choices.0.message.content"
```

### Minimal (auto-detect API endpoint)

```yaml
# target-browser-auto.yaml
url: https://chatbot.example.com/chat
protocol: browser
```

### With login flow

```yaml
# target-browser-login.yaml
url: https://internal-agent.corp.example.com/chat
protocol: browser

browser:
  login_url: https://internal-agent.corp.example.com/login
  login_steps:
    - selector: "#username"
      action: fill
      value: "${AGENT_USERNAME}"
    - selector: "#password"
      action: fill
      value: "${AGENT_PASSWORD}"
    - selector: "button[type='submit']"
      action: click
  input_selector: "#chat-input"
  submit_selector: "#send-button"
  response_selector: ".chat-message.bot"
```

## Running

### CLI

```bash
ziran scan --target target-browser.yaml

# with protocol override
ziran scan --target target.yaml --protocol browser
```

### Python API

```bash
python main.py
```

## How It Works

1. Playwright launches a headless Chromium browser
2. Navigates to the chat URL (optionally runs login steps first)
3. For each attack prompt:
   - Types the message into the chat input
   - Submits via button click or Enter key
   - **Primary:** Intercepts the underlying API response via network monitoring
   - **Fallback:** Extracts text from the DOM if no API call is detected
4. Parsed responses feed into the standard ZIRAN detection pipeline
