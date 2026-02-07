import { NextRequest, NextResponse } from "next/server";
import {
  getMessages,
  createMessage,
  getMessageCount,
  searchMessages,
} from "@/lib/messages";
import { createClient } from "@supabase/supabase-js";

// Admin client for server-side operations
const adminSupabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
);

// GET /api/messages - Fetch all messages or search
export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const userId = searchParams.get("userId");
    const limit = parseInt(searchParams.get("limit") || "100");
    const search = searchParams.get("search");

    if (!userId) {
      return NextResponse.json(
        { error: "User ID is required" },
        { status: 400 }
      );
    }

    let messages;
    if (search) {
      messages = await searchMessages(userId, search, limit);
    } else {
      messages = await getMessages(userId, limit);
    }

    return NextResponse.json({ messages });
  } catch (error) {
    console.error("Error fetching messages:", error);
    return NextResponse.json(
      { error: "Failed to fetch messages" },
      { status: 500 }
    );
  }
}

// POST /api/messages - Create a new message
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { userId, role, content, attachments, conversationId } = body;

    if (!userId || !role || !content) {
      return NextResponse.json(
        { error: "userId, role, and content are required" },
        { status: 400 }
      );
    }

    if (!["user", "assistant"].includes(role)) {
      return NextResponse.json(
        { error: "role must be 'user' or 'assistant'" },
        { status: 400 }
      );
    }

    const message = await createMessage({
      user_id: userId,
      role,
      content,
      attachments: attachments || [],
      conversation_id: conversationId,
    });

    return NextResponse.json({ message }, { status: 201 });
  } catch (error) {
    console.error("Error creating message:", error);
    return NextResponse.json(
      { error: "Failed to create message" },
      { status: 500 }
    );
  }
}
