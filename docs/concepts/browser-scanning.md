# Browser Scanning

## Why Browser Scanning?

Many AI agents are deployed as chat web UIs with no public API. These agents are inaccessible to traditional protocol-level scanners that rely on REST, OpenAI-compatible, MCP, or A2A endpoints.

Browser scanning bridges this gap by using a headless browser (Playwright) to interact with the agent through its chat interface — the same way a real user (or attacker) would.

## How It Works

ZIRAN uses a dual extraction strategy:

### Primary: Network Interception

Most chat UIs are thin wrappers around an API endpoint. The browser adapter monitors all network requests and intercepts the underlying API calls:

1. Playwright types the attack prompt into the chat input
2. The UI sends an HTTP request to the backend API
3. ZIRAN intercepts the JSON response before it reaches the UI
4. The structured response (content, tool calls, token counts) feeds directly into the detection pipeline

This gives the same quality of data as protocol-level scanning, while going through the UI.

### Fallback: DOM Extraction

When no API call is detected (e.g., the agent uses WebSocket or server-rendered responses), ZIRAN falls back to extracting text directly from the DOM:

1. After submitting a message, ZIRAN waits for DOM mutations to settle
2. Queries the configured CSS selector for response elements
3. Extracts the text content of the latest assistant message

DOM mode is less precise — it cannot observe tool calls or token counts — but still enables indicator-based and LLM judge detection.

## Configuration

Browser scanning is configured via YAML target files with `protocol: browser`:

```yaml
url: https://chatbot.example.com/chat
protocol: browser

browser:
  input_selector: "textarea[placeholder*='message']"
  submit_selector: "button[aria-label='Send']"
  api_url_pattern: "**/api/chat/completions"
  response_json_path: "choices.0.message.content"
```

If `api_url_pattern` is omitted, ZIRAN auto-detects the API endpoint by sending a probe message and monitoring which POST requests fire with JSON responses.

## Supported Response Formats

The network interceptor automatically parses:

- **OpenAI format:** `choices[0].message.content` with `tool_calls`
- **Anthropic format:** `content[0].text` with `tool_use` blocks
- **Generic formats:** `response`, `output`, `text`, `answer` fields

## Limitations

- **No streaming support:** Browser adapter uses request/response mode (the base class `stream()` fallback wraps `invoke()`)
- **DOM mode loses tool calls:** When falling back to DOM extraction, tool call information is unavailable
- **Selector fragility:** CSS selectors may break if the UI changes; configure them explicitly for production scans
- **Login complexity:** Simple form-based login is supported; SSO/OAuth flows may require manual session setup
