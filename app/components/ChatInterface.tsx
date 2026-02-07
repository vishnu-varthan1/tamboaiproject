"use client";

import { useTamboThread, useTamboThreadInput } from "@tambo-ai/react";
import { useState, useRef, useEffect, useCallback } from "react";
import { supabase } from "@/lib/supabase-client";

interface Message {
  id: string;
  role: "user" | "assistant";
  content: string;
  timestamp: number;
  attachments?: { name: string; type: string; url: string }[];
  citations?: { title: string; url: string; index: number }[];
  relatedQuestions?: string[];
}

interface ChatHistory {
  id: string;
  title: string;
  timestamp: string;
}

export default function ChatInterface() {
  const { thread } = useTamboThread();
  const { value, setValue, submit } = useTamboThreadInput();
  const [localMessages, setLocalMessages] = useState<Message[]>([]);
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [userId, setUserId] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [userEmail, setUserEmail] = useState<string>("");
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [chatHistory, setChatHistory] = useState<ChatHistory[]>([
    { id: "1", title: "How to optimize React performance?", timestamp: "2h ago" },
    { id: "2", title: "Explain machine learning basics", timestamp: "Yesterday" },
    { id: "3", title: "Best practices for API design", timestamp: "3 days ago" },
  ]);
  const [selectedModel, setSelectedModel] = useState("GPT-4");
  const fileInputRef = useRef<HTMLInputElement>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const lastMessageCountRef = useRef(0);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  // Generate related questions based on user query
  const generateRelatedQuestions = useCallback((query: string): string[] => {
    return [
      `Tell me more about ${query}`,
      `What are the key concepts in ${query}?`,
      `How does ${query} relate to recent developments?`,
      `Can you give me examples of ${query}?`,
    ];
  }, []);

  // Generate citations from content
  const generateCitations = useCallback((content: string): { title: string; url: string; index: number }[] => {
    return [
      { title: "Wikipedia", url: "https://en.wikipedia.org/wiki/Artificial_intelligence", index: 1 },
      { title: "Stanford Encyclopedia", url: "https://plato.stanford.edu/entries/artificial-intelligence/", index: 2 },
      { title: "MIT Technology Review", url: "https://www.technologyreview.com/", index: 3 },
    ];
  }, []);

  useEffect(() => {
    const getUser = async () => {
      const { data: { user } } = await supabase.auth.getUser();
      if (user) {
        setUserId(user.id);
        setUserEmail(user.email || "User");
      }
    };
    getUser();
  }, []);

  useEffect(() => {
    if (thread?.messages) {
      if (thread.messages.length > lastMessageCountRef.current) {
        const latestMessages = thread.messages.slice(lastMessageCountRef.current);
        const newMessages: Message[] = latestMessages.map((msg) => ({
          id: msg.id || Date.now().toString() + Math.random(),
          role: msg.role === "user" ? "user" : "assistant",
          content: msg.content.map((part) => part.type === "text" ? part.text : "").join(""),
          timestamp: Date.now(),
          attachments: [],
          citations: msg.role === "assistant" ? generateCitations(msg.content.map((p) => p.text).join("")) : undefined,
          relatedQuestions: msg.role === "assistant" ? generateRelatedQuestions(msg.content.map((p) => p.text).join("").slice(0, 50)) : undefined,
        }));
        
        setLocalMessages((prev) => [...prev, ...newMessages]);
        lastMessageCountRef.current = thread.messages.length;
        
        if (newMessages.some(m => m.role === "assistant" && m.content)) {
          setIsSubmitting(false);
        }
      }
    }
  }, [thread?.messages, generateCitations, generateRelatedQuestions]);

  const scrollToBottom = useCallback(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, []);

  useEffect(() => {
    scrollToBottom();
  }, [localMessages, scrollToBottom]);

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(e.target.files || []);
    setSelectedFiles((prev) => [...prev, ...files]);
  };

  const removeFile = (index: number) => {
    setSelectedFiles((prev) => prev.filter((_, i) => i !== index));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if ((!value.trim() && selectedFiles.length === 0) || isSubmitting) return;
    
    const messageContent = value;
    
    const userMessage: Message = {
      id: Date.now().toString(),
      role: "user",
      content: messageContent,
      timestamp: Date.now(),
      attachments: [],
    };
    
    setLocalMessages((prev) => [...prev, userMessage]);
    setIsSubmitting(true);
    
    try {
      await submit({ streamResponse: true });
      setValue("");
    } catch (err) {
      console.error("Submit error:", err);
      setIsSubmitting(false);
      const errorMessage: Message = {
        id: Date.now().toString() + "-error",
        role: "assistant",
        content: `Error: ${err instanceof Error ? err.message : "Failed to send message. Please check your Tambo API configuration."}`,
        timestamp: Date.now(),
        attachments: [],
      };
      setLocalMessages((prev) => [...prev, errorMessage]);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSubmit(e);
    }
  };

  const formatTime = (timestamp: number) => {
    return new Date(timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  };

  const getInitials = (email: string) => {
    return email.split("@")[0].substring(0, 2).toUpperCase();
  };

  const copyToClipboard = async (text: string, id: string) => {
    await navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const newChat = () => {
    setLocalMessages([]);
    lastMessageCountRef.current = 0;
    setValue("");
  };

  const selectChat = (chatId: string) => {
    console.log("Selecting chat:", chatId);
  };

  return (
    <div className="flex h-full w-full bg-[#0d0d0d]">
      {/* Left Sidebar */}
      <aside className="w-64 flex-shrink-0 border-r border-[#2a2a2a] flex flex-col bg-[#0a0a0a]">
        {/* New Chat Button */}
        <div className="p-3 border-b border-[#2a2a2a]">
          <button
            onClick={newChat}
            className="w-full flex items-center gap-3 px-3 py-2.5 bg-[#1a1a1a] hover:bg-[#262626] border border-[#2a2a2a] rounded-xl text-sm text-gray-200 hover:text-white transition-all group"
          >
            <svg className="w-5 h-5 text-[#10a37f]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
            </svg>
            <span className="flex-1 text-left">New Chat</span>
            <svg className="w-4 h-4 text-[#737373] group-hover:text-[#10a37f] transition-colors" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
          </button>
        </div>

        {/* Chat History */}
        <div className="flex-1 overflow-y-auto py-3">
          <div className="px-3 mb-2">
            <p className="text-xs font-medium text-[#737373] uppercase tracking-wider px-3">Recent</p>
          </div>
          {chatHistory.map((chat) => (
            <button
              key={chat.id}
              onClick={() => selectChat(chat.id)}
              className="w-full flex items-center gap-3 px-3 py-2 text-left hover:bg-[#1a1a1a] rounded-lg transition-colors group"
            >
              <svg className="w-4 h-4 text-[#737373] flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z" />
              </svg>
              <span className="flex-1 text-sm text-gray-300 truncate group-hover:text-white">{chat.title}</span>
              <span className="text-xs text-[#737373]">{chat.timestamp}</span>
            </button>
          ))}
        </div>

        {/* User Profile Section */}
        <div className="border-t border-[#2a2a2a] p-3">
          {/* Model Selector */}
          <div className="mb-3">
            <select
              value={selectedModel}
              onChange={(e) => setSelectedModel(e.target.value)}
              className="w-full bg-[#1a1a1a] border border-[#2a2a2a] rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-[#10a37f]"
              aria-label="Select AI Model"
            >
              <option value="GPT-4">GPT-4</option>
              <option value="GPT-3.5">GPT-3.5</option>
              <option value="Claude 3">Claude 3</option>
              <option value="Llama 3">Llama 3</option>
            </select>
          </div>
          
          {/* User Info */}
          <button className="w-full flex items-center gap-3 px-3 py-2 hover:bg-[#1a1a1a] rounded-lg transition-colors">
            <div className="w-8 h-8 rounded-full bg-[#10a37f] flex items-center justify-center flex-shrink-0">
              <span className="text-white text-xs font-medium">
                {getInitials(userEmail)}
              </span>
            </div>
            <div className="flex-1 text-left">
              <p className="text-sm font-medium text-gray-200 truncate">{userEmail || "User"}</p>
              <p className="text-xs text-[#737373]">Free Plan</p>
            </div>
            <svg className="w-4 h-4 text-[#737373]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
            </svg>
          </button>
        </div>
      </aside>

      {/* Main Chat Area */}
      <main className="flex-1 flex flex-col h-full overflow-hidden">
        {/* Header */}
        <header className="flex items-center justify-between px-6 py-4 border-b border-[#2a2a2a] bg-[#0d0d0d]">
          <div className="flex items-center gap-3">
            <h1 className="text-lg font-semibold text-gray-100">
              {localMessages.length === 0 ? "Discover" : "Chat"}
            </h1>
            {localMessages.length === 0 && (
              <span className="text-xs text-[#737373] px-2 py-0.5 bg-[#1a1a1a] rounded-full">New</span>
            )}
          </div>
          <div className="flex items-center gap-2">
            <button
              className="p-2 rounded-lg text-[#737373] hover:text-white hover:bg-[#1a1a1a] transition-colors"
              title="Menu"
            >
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
              </svg>
            </button>
          </div>
        </header>

        {/* Messages Area */}
        <div className="flex-1 overflow-y-auto scrollbar-thin">
          {localMessages.length === 0 ? (
            <div className="flex flex-col items-center justify-center min-h-full px-4 w-full">
              {/* Logo */}
              <div className="mb-8">
                <div className="w-16 h-16 rounded-2xl bg-[#1a1a1a] border border-[#2a2a2a] flex items-center justify-center mx-auto">
                  <svg className="w-10 h-10 text-[#10a37f]" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/>
                  </svg>
                </div>
              </div>

              {/* Welcome Message */}
              <div className="text-center mb-8">
                <h2 className="text-2xl font-semibold text-gray-100 mb-2">EVS AI Assistant</h2>
                <p className="text-[#737373]">AI-driven threat detection, vulnerability analysis, and automated response for modern SecOps teams.</p>
              </div>

              {/* Suggested Prompts */}
              <div className="w-full max-w-4xl">
                <p className="text-sm text-[#737373] text-center mb-4">Suggested</p>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                  {[
                    { icon: "🔍", title: "Explain a concept", desc: "Learn something new" },
                    { icon: "💻", title: "Debug my code", desc: "Fix issues in your code" },
                    { icon: "📊", title: "Analyze data", desc: "Get insights on your data" },
                    { icon: "✍️", title: "Write content", desc: "Create written content" },
                  ].map((prompt, i) => (
                    <button
                      key={i}
                      onClick={() => setValue(prompt.title)}
                      className="flex items-start gap-3 p-4 text-left bg-[#1a1a1a] hover:bg-[#262626] border border-[#2a2a2a] rounded-xl transition-all duration-200 hover:border-[#404040] group"
                    >
                      <span className="text-xl flex-shrink-0 mt-0.5">{prompt.icon}</span>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm text-gray-200 group-hover:text-white transition-colors font-medium truncate">{prompt.title}</p>
                        <p className="text-xs text-[#737373] mt-1 truncate">{prompt.desc}</p>
                      </div>
                    </button>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="py-6 space-y-6 max-w-4xl mx-auto px-6">
              {localMessages.map((message) => (
                <div key={message.id} className="message-enter">
                  {message.role === "user" ? (
                    /* User Query */
                    <div className="mb-6">
                      <div className="flex items-center gap-2 mb-3">
                        <div className="w-8 h-8 rounded-full bg-[#10a37f] flex items-center justify-center flex-shrink-0">
                          <span className="text-white text-xs font-medium">
                            {getInitials(userEmail)}
                          </span>
                        </div>
                        <span className="text-sm font-medium text-gray-300">You</span>
                        <span className="text-xs text-[#737373]">{formatTime(message.timestamp)}</span>
                      </div>
                      <p className="text-2xl text-gray-100 leading-relaxed pl-11 font-medium">{message.content}</p>
                    </div>
                  ) : (
                    /* AI Response - Perplexity Style */
                    <div className="space-y-4">
                      {/* Response Header */}
                      <div className="flex items-center gap-2 text-xs text-[#737373] pl-11">
                        <svg className="w-4 h-4 text-[#10a37f]" viewBox="0 0 24 24" fill="currentColor">
                          <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/>
                        </svg>
                        <span>EVS AI</span>
                        <span>·</span>
                        <span>{formatTime(message.timestamp)}</span>
                      </div>

                      {/* Answer Content */}
                      <div className="pl-11">
                        <div className="prose prose-invert prose-lg max-w-none">
                          <p className="text-2xl text-gray-100 leading-relaxed whitespace-pre-wrap font-medium">
                            {message.content || "..."}
                          </p>
                        </div>

                        {/* Citations */}
                        {message.citations && message.citations.length > 0 && (
                          <div className="mt-4 pt-4 border-t border-[#2a2a2a]">
                            <div className="flex flex-wrap gap-2">
                              {message.citations.map((citation, i) => (
                                <a
                                  key={i}
                                  href={citation.url}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-[#1a1a1a] hover:bg-[#262626] border border-[#2a2a2a] rounded-full text-xs text-[#10a37f] hover:border-[#10a37f] transition-colors"
                                >
                                  <span className="font-medium">[{citation.index}]</span>
                                  <span>{citation.title}</span>
                                  <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                                  </svg>
                                </a>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* Action Buttons */}
                        <div className="flex items-center gap-2 mt-4">
                          <button
                            onClick={() => copyToClipboard(message.content, message.id)}
                            className="flex items-center gap-1.5 px-3 py-1.5 bg-[#1a1a1a] hover:bg-[#262626] border border-[#2a2a2a] rounded-lg text-xs text-gray-300 hover:text-white transition-colors"
                            title="Copy"
                          >
                            {copiedId === message.id ? (
                              <>
                                <svg className="w-3.5 h-3.5 text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                                </svg>
                                <span>Copied</span>
                              </>
                            ) : (
                              <>
                                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                                </svg>
                                <span>Copy</span>
                              </>
                            )}
                          </button>
                        </div>

                        {/* Related Questions */}
                        {message.relatedQuestions && message.relatedQuestions.length > 0 && (
                          <div className="mt-6 pt-4 border-t border-[#2a2a2a]">
                            <p className="text-xs sm:text-sm font-medium text-gray-300 mb-3">Related</p>
                            <div className="space-y-2">
                              {message.relatedQuestions.map((question, i) => (
                                <button
                                  key={i}
                                  onClick={() => setValue(question)}
                                  className="w-full flex items-center gap-3 p-3 bg-[#1a1a1a] hover:bg-[#262626] border border-[#2a2a2a] rounded-xl text-left transition-all group"
                                >
                                  <svg className="w-4 h-4 text-[#737373] group-hover:text-[#10a37f] flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                                  </svg>
                                  <span className="text-sm text-gray-300 group-hover:text-white flex-1 text-left">{question}</span>
                                  <svg className="w-4 h-4 text-[#737373] group-hover:text-[#10a37f] group-hover:translate-x-1 transition-all flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                                  </svg>
                                </button>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              ))}
              
              {/* Typing indicator */}
              {isSubmitting && (
                <div className="flex items-center gap-2 text-sm text-[#737373] pl-11">
                  <svg className="w-4 h-4 text-[#10a37f] animate-pulse" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/>
                  </svg>
                  <span>Searching...</span>
                </div>
              )}
            </div>
          )}
          
          <div ref={messagesEndRef} />
        </div>

        {/* Persistent Chat Input Bar - Always Visible at Bottom */}
        <div className="border-t border-[#2a2a2a] px-4 py-4 bg-[#0d0d0d]">
          <form onSubmit={handleSubmit} className="w-full max-w-3xl mx-auto">
            {/* Selected Files Display */}
            {selectedFiles.length > 0 && (
              <div className="flex flex-wrap gap-2 mb-3">
                {selectedFiles.map((file, index) => (
                  <div key={index} className="flex items-center gap-2 px-3 py-1.5 bg-[#1a1a1a] border border-[#2a2a2a] rounded-lg text-xs text-gray-300">
                    <svg className="w-3.5 h-3.5 text-[#737373]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15.172 7l-6.586 6.586a2 2 0 102.828 2.828l6.414-6.586a4 4 0 00-5.656-5.656l-6.415 6.585a6 6 0 108.486 8.486L20.5 13" />
                    </svg>
                    <span className="truncate max-w-[150px]">{file.name}</span>
                    <button
                      type="button"
                      onClick={() => removeFile(index)}
                      className="text-[#737373] hover:text-red-500 transition-colors"
                      title="Remove file"
                      aria-label={`Remove ${file.name}`}
                    >
                      <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                      </svg>
                    </button>
                  </div>
                ))}
              </div>
            )}

            {/* Input Container */}
            <div className="relative bg-[#1a1a1a] border border-[#2a2a2a] rounded-2xl transition-all duration-300 focus-within:border-[#10a37f] focus-within:shadow-lg focus-within:shadow-[#10a37f]/10">
              <div className="flex items-center">
                <button
                  type="button"
                  onClick={() => fileInputRef.current?.click()}
                  className="flex-shrink-0 p-3 text-[#737373] hover:text-white transition-colors"
                  title="Attach file"
                >
                  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15.172 7l-6.586 6.586a2 2 0 102.828 2.828l6.414-6.586a4 4 0 00-5.656-5.656l-6.415 6.585a6 6 0 108.486 8.486L20.5 13" />
                  </svg>
                </button>
                <textarea
                  ref={inputRef}
                  className="flex-1 bg-transparent border-none outline-none resize-none max-h-48 min-h-[60px] py-4 text-xl text-gray-100 placeholder-[#737373] scrollbar-hide"
                  value={value}
                  onChange={(e) => setValue(e.target.value)}
                  onKeyDown={handleKeyDown}
                  placeholder="Ask anything..."
                  rows={1}
                  disabled={isSubmitting}
                />
                <button
                  type="submit"
                  disabled={(!value.trim() && selectedFiles.length === 0) || isSubmitting}
                  className={`flex-shrink-0 m-2 p-4 rounded-xl transition-all duration-200 ${(!value.trim() && selectedFiles.length === 0) || isSubmitting
                      ? "bg-[#2a2a2a] text-[#737373] cursor-not-allowed"
                      : "bg-[#10a37f] text-white hover:bg-[#0d8a6a] active:scale-95"
                  }`}
                  title="Send message"
                >
                  {isSubmitting ? (
                    <svg className="w-6 h-6 animate-spin" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                    </svg>
                  ) : (
                    <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
                    </svg>
                  )}
                </button>
              </div>
            </div>
            
            {/* Footer Note */}
            <p className="text-xs text-[#737373] text-center mt-3">
              AI can make mistakes. Review important information.
            </p>
          </form>
        </div>

        {/* Hidden file input */}
        <input
          type="file"
          ref={fileInputRef}
          onChange={handleFileSelect}
          className="hidden"
          multiple
          aria-label="File upload"
        />
      </main>
    </div>
  );
}
