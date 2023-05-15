import { createContext } from "react";

export enum Error {
  Unauthorized,
  Unexpected,
}

export interface ContextData {
  error: Error | null;
  setError: (error: Error | null) => void;
}

export const Context = createContext<ContextData>({
  error: null,
  setError: () => {},
});
