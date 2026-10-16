import { Injectable } from "@nestjs/common";
import { findUserByEmail, publicUser } from "../store.mjs";

export interface SessionUser {
  id: string;
  email: string;
  name: string;
  role: string;
}

@Injectable()
export class AuthService {
  login(email: string, password: string): { user: SessionUser } | null {
    const user = findUserByEmail(String(email ?? ""));
    if (!user || user.password !== password) return null;
    return { user: publicUser(user) };
  }
}
