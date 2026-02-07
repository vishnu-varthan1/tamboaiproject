import { NextRequest, NextResponse } from "next/server";
import { updateMessage, deleteMessage, getMessages } from "@/lib/messages";
import { createClient } from "@supabase/supabase-js";

// Admin client for server-side operations
const adminSupabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
);

// Helper to get user from request
async function getUserFromRequest(request: NextRequest) {
  // Get user from Authorization header or cookie
  const authHeader = request.headers.get("Authorization");
  const supabaseAuthCookie = request.cookies.get("sb-access-token")?.value;

  if (authHeader) {
    const token = authHeader.replace("Bearer ", "");
    const { data: { user }, error } = await adminSupabase.auth.getUser(token);
    if (!error && user) return user;
  }

  if (supabaseAuthCookie) {
    const { data: { user }, error } = await adminSupabase.auth.getUser(supabaseAuthCookie);
    if (!error && user) return user;
  }

  return null;
}

// PUT /api/messages/[id] - Update a message
export async function PUT(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    const body = await request.json();
    const { userId, content, attachments } = body;

    if (!userId) {
      return NextResponse.json(
        { error: "User ID is required" },
        { status: 400 }
      );
    }

    if (!content && !attachments) {
      return NextResponse.json(
        { error: "At least content or attachments must be provided" },
        { status: 400 }
      );
    }

    const updatedMessage = await updateMessage(id, userId, {
      content,
      attachments,
    });

    return NextResponse.json({ message: updatedMessage });
  } catch (error) {
    console.error("Error updating message:", error);
    return NextResponse.json(
      { error: "Failed to update message" },
      { status: 500 }
    );
  }
}

// DELETE /api/messages/[id] - Delete a message
export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    const { searchParams } = new URL(request.url);
    const userId = searchParams.get("userId");

    if (!userId) {
      return NextResponse.json(
        { error: "User ID is required" },
        { status: 400 }
      );
    }

    await deleteMessage(id, userId);

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error("Error deleting message:", error);
    return NextResponse.json(
      { error: "Failed to delete message" },
      { status: 500 }
    );
  }
}
