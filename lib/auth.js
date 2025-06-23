import { Lucia } from "lucia";
import { BetterSqlite3Adapter } from "@lucia-auth/adapter-sqlite";
import db from "./db";
import { cookies } from "next/headers";

const adapter = new BetterSqlite3Adapter(db, {
  user: "users",
  session: "sessions",
});

const lucia = new Lucia(adapter, {
  sessionCookie: {
    expires: false,
    attributes: {
      secure: process.env.NODE_ENV === "production",
    },
  },
});

export async function createAuthSession(userId) {
  const session = await lucia.createSession(userId, {});
  const sessionCookie = lucia.createSessionCookie(session.id);
  cookies().set(
    sessionCookie.name,
    sessionCookie.value,
    sessionCookie.attributes
  );
  return session;
}

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
