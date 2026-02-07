"use client";

interface Message {
  id: string;
  role: "user" | "assistant";
  content: string;
  timestamp: number;
}

interface ChatMessageProps {
  message: Message;
}

export default function ChatMessage({ message }: ChatMessageProps) {
  const isUser = message.role === "user";

  return (
    <div
      className={`flex w-full ${
        isUser ? "justify-end" : "justify-start"
      } animate-fade-in`}
    >
      <div
        className={`max-w-[85%] md:max-w-[75%] rounded-2xl px-6 py-5 ${
          isUser
            ? "bg-blue-600 text-white rounded-br-md"
            : "bg-gray-100 text-gray-900 rounded-bl-md"
        }`}
      >
        <div className="flex items-center gap-2 mb-2">
          <span
            className={`text-sm font-semibold ${
              isUser ? "text-blue-100" : "text-gray-600"
            }`}
          >
            {isUser ? "You" : "AI Assistant"}
          </span>
        </div>
        <p className="text-2xl leading-relaxed whitespace-pre-wrap font-medium">
          {message.content}
        </p>
      </div>
    </div>
  );
}
