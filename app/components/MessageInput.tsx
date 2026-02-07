"use client";
import { useTamboThreadInput } from "@tambo-ai/react";

export default function MessageInput() {
  const { value, setValue, submit } = useTamboThreadInput();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!value.trim()) return;
    await submit({ streamResponse: true });
  }

  return (
    <form onSubmit={handleSubmit} className="flex gap-3 mt-4">
      <input
        className="border-2 p-4 flex-1 rounded-xl text-xl"
        value={value}
        onChange={(e) => setValue(e.target.value)}
        placeholder="Type your message..."
      />
      <button className="bg-blue-600 text-white px-6 py-4 rounded-xl text-xl font-medium">
        Send
      </button>
    </form>
  );
}
