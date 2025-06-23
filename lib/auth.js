import { Lucia } from "lucia";
import { BetterSqlite3Adapter } from "@lucia-auth/adapter-sqlite";
import db from "./db"; // your SQLite DB instance
import { cookies } from "next/headers";

// Adapter setup
const adapter = new BetterSqlite3Adapter(db, {
  user: "users", // table for users
  session: "sessions", // table for sessions
});

// Lucia instance
const lucia = new Lucia(adapter, {
  sessionCookie: {
    expires: false,
    attributes: {
      secure: process.env.NODE_ENV === "production",
    },
  },
});

// Required if you're using TypeScript, can be skipped for JS
export { lucia };

// ✅ Create session safely
export async function createAuthSession(userId) {
  if (!userId) {
    throw new Error("Cannot create session: userId is missing.");
  }

  const session = await lucia.createSession(userId, {});
  const sessionCookie = lucia.createSessionCookie(session.id);

  cookies().set(
    sessionCookie.name,
    sessionCookie.value,
    sessionCookie.attributes
  );

  return session;
}

// ✅ Verify auth from cookies
export async function verifyAuth() {
  const sessionCookie = cookies().get(lucia.sessionCookieName);

  if (!sessionCookie || !sessionCookie.value) {
    return {
      user: null,
      session: null,
    };
  }

  const result = await lucia.validateSession(sessionCookie.value);

  if (result.session && result.session.fresh) {
    const newSessionCookie = lucia.createSessionCookie(result.session.id);
    cookies().set(
      newSessionCookie.name,
      newSessionCookie.value,
      newSessionCookie.attributes
    );
  }

  if (!result.session) {
    const blankSessionCookie = lucia.createBlankSessionCookie();
    cookies().set(
      blankSessionCookie.name,
      blankSessionCookie.value,
      blankSessionCookie.attributes
    );
  }

  return result;
}

export async function destroySession() {
  const { session } = await verifyAuth();
  if (!session) {
    return {
      errors: {
        session: "No active session found.",
      },
    };
  }
  await lucia.invalidateSession(session.id);
  const blankSessionCookie = lucia.createBlankSessionCookie();
  cookies().set(
    blankSessionCookie.name,
    blankSessionCookie.value,
    blankSessionCookie.attributes
  );
}
