"use client";

import { useState, useEffect } from "react";
import { createClient } from "@/lib/supabase-client";

interface ChatSession {
  id: string;
  title: string;
  created_at: string;
  updated_at: string;
  message_count: number;
}

interface ChatHistoryProps {
  onSelectChat: (chatId: string) => void;
  currentChatId: string | null;
}

export default function ChatHistory({ onSelectChat, currentChatId }: ChatHistoryProps) {
  const [sessions, setSessions] = useState<ChatSession[]>([]);
  const [loading, setLoading] = useState(true);
  const [userId, setUserId] = useState<string | null>(null);

  useEffect(() => {
    const getUserAndSessions = async () => {
      const { data: { user } } = await createClient().auth.getUser();
      if (user) {
        setUserId(user.id);
        fetchChatSessions(user.id);
      } else {
        setLoading(false);
      }
    };
    getUserAndSessions();
  }, []);

  const fetchChatSessions = async (userId: string) => {
    try {
      // For demo, create mock sessions since we don't have the database table yet
      // In production, you would query Supabase
      const mockSessions: ChatSession[] = [
        {
          id: "1",
          title: "Help with coding",
          created_at: new Date(Date.now() - 86400000).toISOString(),
          updated_at: new Date(Date.now() - 86400000).toISOString(),
          message_count: 5,
        },
        {
          id: "2",
          title: "Writing assistance",
          created_at: new Date(Date.now() - 172800000).toISOString(),
          updated_at: new Date(Date.now() - 172800000).toISOString(),
          message_count: 3,
        },
        {
          id: "3",
          title: "General questions",
          created_at: new Date(Date.now() - 259200000).toISOString(),
          updated_at: new Date(Date.now() - 259200000).toISOString(),
          message_count: 8,
        },
      ];
      setSessions(mockSessions);
    } catch (error) {
      console.error("Error fetching sessions:", error);
    } finally {
      setLoading(false);
    }
  };

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    const now = new Date();
    const diffTime = Math.abs(now.getTime() - date.getTime());
    const diffDays = Math.floor(diffTime / (1000 * 60 * 60 * 24));

    if (diffDays === 0) return "Today";
    if (diffDays === 1) return "Yesterday";
    if (diffDays < 7) return `${diffDays} days ago`;
    return date.toLocaleDateString();
  };

  const createNewChat = async () => {
    if (!userId) return;

    // Create a new chat session
    const newSession: ChatSession = {
      id: Date.now().toString(),
      title: "New Chat",
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      message_count: 0,
    };

    setSessions((prev) => [newSession, ...prev]);
    onSelectChat(newSession.id);
  };

  const deleteChat = async (e: React.MouseEvent, chatId: string) => {
    e.stopPropagation();
    setSessions((prev) => prev.filter((s) => s.id !== chatId));
    if (currentChatId === chatId) {
      onSelectChat("");
    }
  };

  if (loading) {
    return (
      <div className="flex-1 overflow-y-auto p-4">
        <div className="space-y-3">
          {[1, 2, 3].map((i) => (
            <div key={i} className="animate-pulse">
              <div className="h-10 bg-[#262626] rounded-lg" />
            </div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="flex-1 overflow-y-auto">
      {/* Chat History Section */}
      <div className="p-4 pb-2">
        <p className="text-xs text-[#737373] uppercase tracking-wider mb-2">Recent Chats</p>
      </div>

      {sessions.length === 0 ? (
        <div className="px-4 pb-4">
          <p className="text-sm text-[#737373] text-center py-4">
            No chat history yet.{<br />}Start a new conversation!
          </p>
        </div>
      ) : (
        <div className="px-4 pb-4 space-y-1">
          {sessions.map((session) => (
            <button
              key={session.id}
              onClick={() => onSelectChat(session.id)}
              className={`w-full flex items-center justify-between gap-2 px-3 py-2.5 rounded-lg text-left transition-colors group ${
                currentChatId === session.id
                  ? "bg-[#2a2a2a] text-white"
                  : "text-gray-300 hover:bg-[#262626]"
              }`}
            >
              <div className="flex items-center gap-3 min-w-0 flex-1">
                <svg
                  className={`w-4 h-4 flex-shrink-0 ${
                    currentChatId === session.id ? "text-[#10a37f]" : "text-[#737373]"
                  }`}
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z"
                  />
                </svg>
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium truncate">{session.title}</p>
                  <p className="text-xs text-[#737373]">{formatDate(session.updated_at)}</p>
                </div>
              </div>
              <span
                role="button"
                tabIndex={0}
                onClick={(e) => deleteChat(e, session.id)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    deleteChat(e, session.id);
                  }
                }}
                className="opacity-0 group-hover:opacity-100 p-1.5 text-[#737373] hover:text-red-400 rounded-lg hover:bg-[#404040] transition-all cursor-pointer"
              >
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"
                  />
                </svg>
              </span>
            </button>
          ))}
        </div>
      )}

      {/* New Chat Button */}
      <div className="p-4 pt-2">
        <button
          onClick={createNewChat}
          className="w-full flex items-center justify-center gap-2 bg-[#10a37f] hover:bg-[#0d8a6a] text-white px-4 py-2.5 rounded-xl font-medium btn-transition"
        >
          <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
          </svg>
          New Chat
        </button>
      </div>
    </div>
  );
}
