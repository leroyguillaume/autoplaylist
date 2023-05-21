import jwt_decode from "jwt-decode";
import { createContext } from "react";
import { JWT_LOCAL_STORAGE_KEY } from "./api";
import { Role } from "./domain";

export interface AuthenticatedUser {
  id: string;
  role: Role;
}

export enum Error {
  QueryAlreadyExists,
  Unauthorized,
  Unexpected,
}

export enum Info {
  BaseSyncWillStart,
  QueryCreated,
  QueryDeleted,
}

export interface ContextData {
  authUser: AuthenticatedUser | null;
  error: Error | null;
  info: Info | null;
  setAuthUser: (authUser: AuthenticatedUser | null) => void;
  setError: (error: Error | null) => void;
  setInfo: (info: Info | null) => void;
}

export const Context = createContext<ContextData>({
  authUser: null,
  error: null,
  info: null,
  setAuthUser: () => {},
  setError: () => {},
  setInfo: () => {},
});

export function loadAuthenticatedUser(): AuthenticatedUser | null {
  const jwt = localStorage.getItem(JWT_LOCAL_STORAGE_KEY);
  if (jwt === null) {
    return null;
  }
  const jwt_decoded: any = jwt_decode(jwt);
  const now = Math.floor(Date.now() / 1000);
  if (now >= jwt_decoded.exp) {
    return null;
  }
  return {
    id: jwt_decoded.sub,
    role: jwt_decoded.role,
  };
}

export function pageNumberFromQuery(
  key: string,
  params: URLSearchParams
): number {
  let param = params.get(key);
  if (param == null) {
    return 1;
  }
  try {
    return parseInt(param);
  } catch {
    return 1;
  }
}
