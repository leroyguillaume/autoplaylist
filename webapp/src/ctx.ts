import { createContext } from "react";

export enum Error {
  QueryAlreadyExists,
  Unauthorized,
  Unexpected,
}

export enum Info {
  QueryCreated,
}

export interface ContextData {
  error: Error | null;
  info: Info | null;
  setError: (error: Error | null) => void;
  setInfo: (info: Info | null) => void;
}

export const Context = createContext<ContextData>({
  error: null,
  info: null,
  setError: () => {},
  setInfo: () => {},
});
