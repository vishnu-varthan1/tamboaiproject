# AI Chat Widget - Embeddable

Lightweight, embeddable AI chat widget that can be placed on external websites.

## Files

- [`chat-widget.html`](chat-widget.html) - Standalone HTML widget (open directly in browser)
- [`embed.js`](embed.js) - JavaScript library for embedding on websites

## Usage

### Option 1: Standalone HTML

Open [`chat-widget.html`](chat-widget.html) directly in any web browser. This is a self-contained widget that works offline.

### Option 2: Embed on Your Website

Add the script to your website:

```html
<script src="https://your-domain.com/widgets/embed.js"></script>
<script>
  window.aiChatWidget.init({
    apiUrl: 'https://your-api.com/chat',
    title: 'AI Assistant',
    primaryColor: '#10a37f',
    placeholder: 'Ask me anything...',
    welcomeMessage: 'How can I help you today?'
  });
</script>
```

### Option 3: Custom Message Handler

For full control over the AI response:

```html
<script src="https://your-domain.com/widgets/embed.js"></script>
<script>
  // Initialize without API URL
  window.aiChatWidget.init({
    title: 'My AI Chat',
    primaryColor: '#6366f1'
  });

  // Add custom message handler
  window.aiChatWidget.addMessageHandler(async (message) => {
    // Call your AI API here
    const response = await fetch('https://your-ai-api.com/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ prompt: message })
    });
    const data = await response.json();
    return { response: data.answer };
  });
</script>
```

## API

### `window.aiChatWidget.init(options)`

Initialize the widget with configuration options:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `apiUrl` | string | `null` | URL endpoint for AI responses |
| `title` | string | `'AI Assistant'` | Widget title |
| `primaryColor` | string | `'#10a37f'` | Primary accent color |
| `placeholder` | string | `'Type your message...'` | Input placeholder text |
| `welcomeMessage` | string | `'How can I help you?'` | Welcome message |

### `window.aiChatWidget.open()`

Open the chat window programmatically.

### `window.aiChatWidget.close()`

Close the chat window programmatically.

### `window.aiChatWidget.setConfig(options)`

