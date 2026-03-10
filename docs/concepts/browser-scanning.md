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

## Smart UI Auto-Discovery

Many chatbot UIs don't show the chat input immediately on page load — they hide it behind a launcher button ("Start Chat", "Open", a chat bubble icon) or behind a cookie consent banner. ZIRAN automatically handles these patterns:

1. **Cookie/consent banner dismissal:** Detects and dismisses common cookie banners (supports English, Dutch, and other common languages)
2. **Chat launcher detection:** Finds and clicks "Start Chat" / "Open Chat" buttons using text-based, attribute-based, and structural heuristics
3. **Input discovery:** Probes for the actual chat input element (`textarea`, `input`, `contenteditable`, `[role='textbox']`) after the chat UI is opened
4. **Submit button discovery:** Locates the send/submit button adjacent to the chat input

Auto-discovery runs by default. If it causes issues with a specific UI, disable it and provide explicit selectors:

```yaml
browser:
  auto_discover: false
  input_selector: "#my-chat-input"
  submit_selector: "#my-send-button"
```

## Option / Quick-Reply Handling

Many chatbots are hybrid — they mix free-text input with clickable option buttons (quick replies, chips, suggestion buttons). These appear at the start of a conversation ("What can I help you with?") or mid-conversation ("Pick a topic:").

ZIRAN detects and navigates through option menus automatically:

1. **Preferred options:** If `prefer_options` is set, tries those first (case-insensitive substring match)
2. **Detection:** After the chat UI opens, ZIRAN scans for common option button patterns (`[class*='quick-reply']`, `[class*='chip']`, `[role='option']`, etc.)
3. **Free-text navigation:** Looks for "Something else" / "Other" / "Iets anders" options that typically lead to free-text mode
4. **Click-through:** If no free-text option exists, clicks through the first available option to navigate deeper into the conversation tree
5. **Depth limiting:** Stops after `max_option_depth` levels (default: 3) to prevent infinite loops

The strategy is configurable:

```yaml
browser:
  initial_options: auto          # auto | click_through | type_through | skip
  max_option_depth: 3            # max menu levels to navigate
  option_selector: ".my-chips"   # custom selector (empty = auto-detect)
  prefer_options:                # domain-specific options to prefer
    - "Ask a question"
    - "Vraag stellen"
```

Use `prefer_options` for hybrid bots where you know which option leads to the LLM-powered free-text mode. This is especially useful when the built-in heuristics don't cover the specific option labels of your target chatbot.

Option buttons detected during attack execution are included in the response metadata for analysis.

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
