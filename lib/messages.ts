import { supabase } from "./supabase";

export interface ChatMessage {
  id: string;
  user_id: string;
  role: "user" | "assistant";
  content: string;
  attachments?: { name: string; type: string; url: string }[];
  created_at: string;
  updated_at: string;
  conversation_id?: string;
}

export interface CreateMessageInput {
  user_id: string;
  role: "user" | "assistant";
  content: string;
  attachments?: { name: string; type: string; url: string }[];
  conversation_id?: string;
}

export interface UpdateMessageInput {
  content?: string;
  attachments?: { name: string; type: string; url: string }[];
}

/**
 * Fetch all messages for a user, ordered by creation time
 */
export async function getMessages(userId: string, limit = 100): Promise<ChatMessage[]> {
  const { data, error } = await supabase
    .from("chat_messages")
    .select("*")
    .eq("user_id", userId)
    .order("created_at", { ascending: true })
    .limit(limit);

  if (error) {
    console.error("Error fetching messages:", error);
    throw error;
  }

  return data || [];
}

/**
 * Fetch messages for a specific conversation
 */
export async function getConversationMessages(
  conversationId: string,
  limit = 100
): Promise<ChatMessage[]> {
  const { data, error } = await supabase
    .from("chat_messages")
    .select("*")
    .eq("conversation_id", conversationId)
    .order("created_at", { ascending: true })
    .limit(limit);

  if (error) {
    console.error("Error fetching conversation messages:", error);
    throw error;
  }

  return data || [];
}

/**
 * Get recent conversations for a user
 */
export async function getRecentConversations(
  userId: string,
  limit = 20
): Promise<ChatMessage[]> {
  const { data, error } = await supabase
    .from("chat_messages")
    .select("*")
    .eq("user_id", userId)
    .order("created_at", { ascending: false })
    .limit(limit);

  if (error) {
    console.error("Error fetching recent conversations:", error);
    throw error;
  }

  return data || [];
}

/**
 * Create a new message
 */
export async function createMessage(input: CreateMessageInput): Promise<ChatMessage> {
  const { data, error } = await supabase
    .from("chat_messages")
    .insert({
      user_id: input.user_id,
      role: input.role,
      content: input.content,
      attachments: input.attachments || [],
      conversation_id: input.conversation_id,
    })
    .select()
    .single();

  if (error) {
    console.error("Error creating message:", error);
    throw error;
  }

  return data;
}

/**
 * Update an existing message
 */
export async function updateMessage(
  messageId: string,
  userId: string,
  input: UpdateMessageInput
): Promise<ChatMessage> {
  const { data, error } = await supabase
    .from("chat_messages")
    .update({
      content: input.content,
      attachments: input.attachments,
    })
    .eq("id", messageId)
    .eq("user_id", userId)
    .select()
    .single();

  if (error) {
    console.error("Error updating message:", error);
    throw error;
  }

  return data;
}

/**
 * Delete a message
 */
export async function deleteMessage(messageId: string, userId: string): Promise<void> {
  const { error } = await supabase
    .from("chat_messages")
    .delete()
    .eq("id", messageId)
    .eq("user_id", userId);

  if (error) {
    console.error("Error deleting message:", error);
    throw error;
  }
}

/**
 * Delete all messages for a user
 */
export async function deleteAllUserMessages(userId: string): Promise<void> {
  const { error } = await supabase
    .from("chat_messages")
    .delete()
    .eq("user_id", userId);

  if (error) {
    console.error("Error deleting all user messages:", error);
    throw error;
  }
}

/**
 * Subscribe to real-time message updates
 */
export function subscribeToMessages(
  userId: string,
  callback: (message: ChatMessage) => void
) {
  const subscription = supabase
    .channel(`messages:${userId}`)
    .on(
      "postgres_changes",
      {
        event: "INSERT",
        schema: "public",
        table: "chat_messages",
        filter: `user_id=eq.${userId}`,
      },
      (payload) => {
        callback(payload.new as ChatMessage);
      }
    )
    .subscribe();

  return subscription;
}

/**
 * Get message count for a user
 */
export async function getMessageCount(userId: string): Promise<number> {
  const { count, error } = await supabase
    .from("chat_messages")
    .select("*", { count: "exact", head: true })
    .eq("user_id", userId);

  if (error) {
    console.error("Error getting message count:", error);
    throw error;
  }

  return count || 0;
}

/**
 * Search messages by content
 */
export async function searchMessages(
  userId: string,
  searchTerm: string,
  limit = 50
): Promise<ChatMessage[]> {
  const { data, error } = await supabase
    .from("chat_messages")
    .select("*")
    .eq("user_id", userId)
    .ilike("content", `%${searchTerm}%`)
    .order("created_at", { ascending: false })
    .limit(limit);

  if (error) {
    console.error("Error searching messages:", error);
    throw error;
  }

  return data || [];
}
