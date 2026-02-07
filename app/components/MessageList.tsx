"use client";
import { useTamboThread } from "@tambo-ai/react";
// Removed unused useEffect and useState imports

export default function MessageList() {
  const { thread } = useTamboThread();

  if (!thread) return <p>Loading...</p>;

  return (
    <div className="h-96 overflow-y-auto border p-4 rounded">
      {thread.messages.length === 0 ? (
        <p className="text-gray-500 text-center">Send a message to start the conversation!</p>
      ) : (
        thread.messages.map((msg) => (
          <div 
            key={msg.id} 
            className={`mb-3 p-3 rounded ${
              msg.role === "user" ? "bg-blue-100 ml-8" : "bg-gray-100 mr-8"
            }`}
          >
            <p className="font-bold text-sm mb-1">
              {msg.role === "user" ? "👤 You" : "🤖 AI Assistant"}
            </p>
            {msg.content.map((part, i) =>
              part.type === "text" ? <p key={i}>{part.text}</p> : null
            )}
          </div>
        ))
      )}
    </div>
  );
}
