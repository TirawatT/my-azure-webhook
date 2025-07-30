// app/api/hello/route.js

import { NextResponse } from "next/server";

export async function GET(request) {
  // You can access query parameters from the request object:
  const { searchParams } = new URL(request.url);
  const name = searchParams.get("name") || "World";

  // Return a JSON response
  return NextResponse.json({ message: `Hello, ${name}!` }, { status: 200 });
}
