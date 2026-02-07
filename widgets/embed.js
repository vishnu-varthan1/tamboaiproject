/**
 * AI Chat Widget - Embeddable Script
 * Usage: Add this script to any website and initialize with:
 *   window.aiChatWidget.init({ apiUrl: 'https://your-api.com/chat' });
 */

(function() {
  'use strict';

  const WIDGET_VERSION = '1.0.0';
  const DEFAULT_CONFIG = {
    apiUrl: null,
    title: 'AI Assistant',
    primaryColor: '#10a37f',
    position: 'bottom-right',
    placeholder: 'Type your message...',
    welcomeMessage: 'How can I help you?',
  };

  class AIChatWidget {
    constructor() {
      this.config = { ...DEFAULT_CONFIG };
      this.isOpen = false;
      this.messages = [];
      this.isTyping = false;
      this.isInitialized = false;
    }

    init(options = {}) {
      if (this.isInitialized) {
        console.warn('AI Chat Widget is already initialized');
        return;
      }

      this.config = { ...this.config, ...options };
      this.createStyles();
      this.createWidget();
      this.bindEvents();
      this.isInitialized = true;

      console.log('AI Chat Widget initialized v' + WIDGET_VERSION);
    }

    createStyles() {
      const css = `
        .ai-chat-widget-container {
          position: fixed;
          bottom: 20px;
          right: 20px;
          z-index: 999999;
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        }

        .ai-chat-widget-toggle {
          width: 60px;
          height: 60px;
          border-radius: 50%;
          background: ${this.config.primaryColor};
          border: none;
          cursor: pointer;
          box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
          display: flex;
          align-items: center;
          justify-content: center;
          transition: transform 0.3s ease;
        }

        .ai-chat-widget-toggle:hover {
          transform: scale(1.1);
        }

        .ai-chat-widget-toggle svg {
          width: 28px;
          height: 28px;
          fill: white;
        }

        .ai-chat-widget-window {
          position: absolute;
          bottom: 80px;
          right: 0;
          width: 380px;
          height: 500px;
          background: #1a1a1a;
          border-radius: 16px;
          box-shadow: 0 8px 40px rgba(0, 0, 0, 0.4);
          display: none;
          flex-direction: column;
          overflow: hidden;
          border: 1px solid #2a2a2a;
        }

        .ai-chat-widget-window.open {
          display: flex;
        }

        .ai-chat-widget-header {
          padding: 16px 20px;
          border-bottom: 1px solid #2a2a2a;
          display: flex;
          align-items: center;
          justify-content: space-between;
          background: #0d0d0d;
        }

        .ai-chat-widget-header-left {
          display: flex;
          align-items: center;
          gap: 12px;
        }

        .ai-chat-widget-avatar {
          width: 40px;
          height: 40px;
          border-radius: 12px;
          background: ${this.config.primaryColor};
          display: flex;
          align-items: center;
          justify-content: center;
        }

        .ai-chat-widget-avatar svg {
          width: 24px;
          height: 24px;
          fill: white;
        }

        .ai-chat-widget-title {
          color: #ffffff;
          font-size: 15px;
          font-weight: 600;
        }

        .ai-chat-widget-status {
          color: #737373;
          font-size: 12px;
          display: flex;
          align-items: center;
          gap: 6px;
          margin-top: 2px;
        }

        .ai-chat-widget-status-dot {
          width: 8px;
          height: 8px;
          border-radius: 50%;
          background: #22c55e;
        }

        .ai-chat-widget-close {
          width: 36px;
          height: 36px;
          border-radius: 8px;
          background: transparent;
          border: none;
          cursor: pointer;
          display: flex;
          align-items: center;
          justify-content: center;
          transition: background 0.2s;
        }

        .ai-chat-widget-close:hover {
          background: #2a2a2a;
        }

        .ai-chat-widget-close svg {
          width: 20px;
          height: 20px;
          fill: #737373;
        }

        .ai-chat-widget-messages {
          flex: 1;
          overflow-y: auto;
          padding: 20px;
          display: flex;
          flex-direction: column;
          gap: 16px;
        }

        .ai-chat-widget-message {
          display: flex;
          flex-direction: column;
          max-width: 85%;
          animation: fadeIn 0.3s ease;
        }

        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(10px); }
          to { opacity: 1; transform: translateY(0); }
        }

        .ai-chat-widget-message.user {
          align-self: flex-end;
        }

        .ai-chat-widget-message.ai {
          align-self: flex-start;
        }

        .ai-chat-widget-message-content {
          padding: 12px 16px;
          border-radius: 16px;
          font-size: 14px;
          line-height: 1.5;
        }

        .ai-chat-widget-message.user .ai-chat-widget-message-content {
          background: ${this.config.primaryColor};
          color: white;
          border-bottom-right-radius: 4px;
        }

        .ai-chat-widget-message.ai .ai-chat-widget-message-content {
          background: #1a1a1a;
          color: #ffffff;
          border: 1px solid #2a2a2a;
          border-bottom-left-radius: 4px;
        }

        .ai-chat-widget-message-meta {
          font-size: 11px;
          color: #737373;
          margin-top: 6px;
          padding: 0 4px;
        }

        .ai-chat-widget-message.user .ai-chat-widget-message-meta {
          text-align: right;
        }

        .ai-chat-widget-typing {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 12px 16px;
          background: #1a1a1a;
          border: 1px solid #2a2a2a;
          border-radius: 16px;
          border-bottom-left-radius: 4px;
          max-width: 85%;
          align-self: flex-start;
        }

        .ai-chat-widget-typing-dot {
          width: 8px;
          height: 8px;
          border-radius: 50%;
          background: #737373;
          animation: typing 1.4s infinite;
        }

        .ai-chat-widget-typing-dot:nth-child(2) {
          animation-delay: 0.2s;
        }

        .ai-chat-widget-typing-dot:nth-child(3) {
          animation-delay: 0.4s;
        }

        @keyframes typing {
          0%, 60%, 100% { transform: translateY(0); }
          30% { transform: translateY(-4px); }
        }

        .ai-chat-widget-input-container {
          padding: 16px 20px;
          border-top: 1px solid #2a2a2a;
          background: #0d0d0d;
        }

        .ai-chat-widget-input-wrapper {
          display: flex;
          align-items: flex-end;
          gap: 10px;
          background: #1a1a1a;
          border: 1px solid #2a2a2a;
          border-radius: 12px;
          padding: 4px 4px 4px 16px;
          transition: border-color 0.2s;
        }

        .ai-chat-widget-input-wrapper:focus-within {
          border-color: ${this.config.primaryColor};
        }

        .ai-chat-widget-input {
          flex: 1;
          background: transparent;
          border: none;
          outline: none;
          color: #ffffff;
          font-size: 14px;
          resize: none;
          max-height: 120px;
          min-height: 44px;
          line-height: 1.5;
          padding: 12px 0;
        }

        .ai-chat-widget-input::placeholder {
          color: #737373;
        }

        .ai-chat-widget-send {
          width: 40px;
          height: 40px;
          border-radius: 10px;
          background: ${this.config.primaryColor};
          border: none;
          cursor: pointer;
          display: flex;
          align-items: center;
          justify-content: center;
          transition: opacity 0.2s;
          flex-shrink: 0;
        }

        .ai-chat-widget-send:hover {
          opacity: 0.9;
        }

        .ai-chat-widget-send:disabled {
          opacity: 0.5;
          cursor: not-allowed;
        }

        .ai-chat-widget-send svg {
          width: 18px;
          height: 18px;
          fill: white;
        }

        .ai-chat-widget-welcome {
          flex: 1;
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          padding: 40px 20px;
          text-align: center;
        }

        .ai-chat-widget-welcome-icon {
          width: 64px;
          height: 64px;
          border-radius: 16px;
          background: ${this.config.primaryColor};
          display: flex;
          align-items: center;
          justify-content: center;
          margin-bottom: 20px;
        }

        .ai-chat-widget-welcome-icon svg {
          width: 32px;
          height: 32px;
          fill: white;
        }

        .ai-chat-widget-welcome h2 {
          color: #ffffff;
          font-size: 18px;
          font-weight: 600;
          margin-bottom: 8px;
        }

        .ai-chat-widget-welcome p {
          color: #737373;
          font-size: 13px;
          line-height: 1.5;
          max-width: 280px;
        }

        .ai-chat-widget-messages::-webkit-scrollbar {
          width: 6px;
        }

        .ai-chat-widget-messages::-webkit-scrollbar-track {
          background: transparent;
        }

        .ai-chat-widget-messages::-webkit-scrollbar-thumb {
          background: #2a2a2a;
          border-radius: 3px;
        }

        .ai-chat-widget-messages::-webkit-scrollbar-thumb:hover {
          background: #3a3a3a;
        }

        @media (max-width: 420px) {
          .ai-chat-widget-window {
            width: calc(100vw - 40px);
            right: -10px;
          }
        }
      `;

      const style = document.createElement('style');
      style.id = 'ai-chat-widget-styles';
      style.textContent = css;
      document.head.appendChild(style);
    }

    createWidget() {
      const container = document.createElement('div');
      container.className = 'ai-chat-widget-container';
      container.innerHTML = `
        <div class="ai-chat-widget-window" id="aiChatWidgetWindow">
          <div class="ai-chat-widget-header">
            <div class="ai-chat-widget-header-left">
              <div class="ai-chat-widget-avatar">
                <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/></svg>
              </div>
              <div>
                <div class="ai-chat-widget-title">${this.config.title}</div>
                <div class="ai-chat-widget-status">
                  <span class="ai-chat-widget-status-dot"></span>
                  Online
                </div>
              </div>
            </div>
            <button class="ai-chat-widget-close" id="aiChatWidgetClose" aria-label="Close chat">
              <svg viewBox="0 0 24 24"><path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/></svg>
            </button>
          </div>
          
          <div class="ai-chat-widget-messages" id="aiChatWidgetMessages">
            <div class="ai-chat-widget-welcome" id="aiChatWidgetWelcome">
              <div class="ai-chat-widget-welcome-icon">
                <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/></svg>
              </div>
              <h2>${this.config.title}</h2>
              <p>${this.config.welcomeMessage}</p>
            </div>
          </div>
          
          <div class="ai-chat-widget-typing" id="aiChatWidgetTyping" style="display: none;">
            <div class="ai-chat-widget-typing-dot"></div>
            <div class="ai-chat-widget-typing-dot"></div>
            <div class="ai-chat-widget-typing-dot"></div>
          </div>
          
          <div class="ai-chat-widget-input-container">
            <div class="ai-chat-widget-input-wrapper">
              <textarea 
                class="ai-chat-widget-input" 
                id="aiChatWidgetInput" 
                placeholder="${this.config.placeholder}"
                rows="1"
              ></textarea>
              <button class="ai-chat-widget-send" id="aiChatWidgetSend" disabled aria-label="Send message">
                <svg viewBox="0 0 24 24"><path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z"/></svg>
              </button>
            </div>
          </div>
        </div>
        
        <button class="ai-chat-widget-toggle" id="aiChatWidgetToggle" aria-label="Open chat">
          <svg viewBox="0 0 24 24"><path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm0 14H6l-2 2V4h16v12z"/></svg>
        </button>
      `;

      document.body.appendChild(container);
    }

    bindEvents() {
      const windowEl = document.getElementById('aiChatWidgetWindow');
      const toggleEl = document.getElementById('aiChatWidgetToggle');
      const closeEl = document.getElementById('aiChatWidgetClose');
      const messagesEl = document.getElementById('aiChatWidgetMessages');
      const welcomeEl = document.getElementById('aiChatWidgetWelcome');
      const typingEl = document.getElementById('aiChatWidgetTyping');
      const inputEl = document.getElementById('aiChatWidgetInput');
      const sendEl = document.getElementById('aiChatWidgetSend');

      toggleEl.addEventListener('click', () => this.toggleChat());
      closeEl.addEventListener('click', () => this.closeChat());
      sendEl.addEventListener('click', () => this.handleSend());
      inputEl.addEventListener('input', () => this.handleInput());
      inputEl.addEventListener('keydown', (e) => this.handleKeyDown(e));

      this.windowEl = windowEl;
      this.toggleEl = toggleEl;
      this.messagesEl = messagesEl;
      this.welcomeEl = welcomeEl;
      this.typingEl = typingEl;
      this.inputEl = inputEl;
      this.sendEl = sendEl;
    }

    toggleChat() {
      this.isOpen = !this.isOpen;
      this.windowEl.classList.toggle('open', this.isOpen);
      
      if (this.isOpen && this.messages.length === 0) {
        this.welcomeEl.style.display = 'flex';
      } else {
        this.welcomeEl.style.display = 'none';
      }
    }

    closeChat() {
      this.isOpen = false;
      this.windowEl.classList.remove('open');
    }

    getCurrentTime() {
      return new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }

    escapeHtml(text) {
      const div = document.createElement('div');
      div.textContent = text;
      return div.innerHTML;
    }

    addMessage(content, role) {
      const message = {
        id: Date.now(),
        content,
        role,
        timestamp: this.getCurrentTime()
      };
      this.messages.push(message);
      
      if (this.messages.length === 1) {
        this.welcomeEl.style.display = 'none';
      }

      const messageEl = document.createElement('div');
      messageEl.className = `ai-chat-widget-message ${role}`;
      messageEl.innerHTML = `
        <div class="ai-chat-widget-message-content">${this.escapeHtml(content)}</div>
        <div class="ai-chat-widget-message-meta">${message.timestamp}</div>
      `;
      this.messagesEl.appendChild(messageEl);
      this.messagesEl.scrollTop = this.messagesEl.scrollHeight;
    }

    showTyping() {
      this.isTyping = true;
      this.typingEl.style.display = 'flex';
      this.messagesEl.scrollTop = this.messagesEl.scrollHeight;
    }

    hideTyping() {
      this.isTyping = false;
      this.typingEl.style.display = 'none';
    }

    async sendMessageToAPI(message) {
      if (!this.config.apiUrl) {
        return { response: 'This is a placeholder response. Configure apiUrl to connect to your AI endpoint.' };
      }

      try {
        const response = await fetch(this.config.apiUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ message }),
        });

        if (!response.ok) {
          throw new Error('API request failed');
        }

        return await response.json();
      } catch (error) {
        console.error('Chat API error:', error);
        return { response: 'Sorry, I encountered an error. Please try again.' };
      }
    }

    async handleSend() {
      const content = this.inputEl.value.trim();
      if (!content || this.isTyping) return;
      
      this.addMessage(content, 'user');
      this.inputEl.value = '';
      this.sendEl.disabled = true;
      
      this.showTyping();
      
      const response = await this.sendMessageToAPI(content);
      
      this.hideTyping();
      this.addMessage(response.response, 'ai');
    }

    handleInput() {
      this.sendEl.disabled = !this.inputEl.value.trim();
      
      this.inputEl.style.height = 'auto';
      this.inputEl.style.height = Math.min(this.inputEl.scrollHeight, 120) + 'px';
    }

    handleKeyDown(e) {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        if (this.inputEl.value.trim()) {
          this.handleSend();
        }
      }
    }

    // Public API
    open() {
      this.toggleChat();
    }

    close() {
      this.closeChat();
    }

    setConfig(options) {
      this.config = { ...this.config, ...options };
    }

    addMessageHandler(handler) {
      this.sendMessageToAPI = handler;
    }
  }

  // Create global instance
  window.aiChatWidget = new AIChatWidget();
})();
