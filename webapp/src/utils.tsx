import { jwtDecode } from "jwt-decode";
import {
  type Auth,
  PATH_AUTH,
  PATH_SPOTIFY,
  AppError,
  PATH_FORBIDDEN,
  type AppContextState,
  LOCAL_STORAGE_KEY_TOKEN,
  PATH_PLAYLIST,
} from ".";
import { type Role } from "./api";
import { type NavigateFunction, type Location } from "react-router";

// Global vars

let cfg: Config | null = null;

// Config

interface Config {
  apiUrl: string;
}

// backPath

export function backPath(loc: Location<any>): string {
  return loc.state?.history?.[loc.state?.history?.length - 1] ?? PATH_PLAYLIST;
}

// config

export async function config(): Promise<Config> {
  if (cfg === null) {
    return await fetch("/config.json")
      .then(async (resp) => {
        const config = await resp.json();
        cfg = config;
        return await Promise.resolve(config);
      })
      .catch(async () => {
        return await Promise.reject(AppError.Config);
      });
  } else {
    return await Promise.resolve(cfg);
  }
}

// decodeToken

export function decodeToken(token: string): Auth | null {
  try {
    const payload = jwtDecode<{
      exp: number;
      role: Role;
      sub: string;
    }>(token);
    const exp = new Date(payload.exp * 1000);
    if (exp < new Date()) {
      return null;
    }
    return { id: payload.sub, role: payload.role };
  } catch (err) {
    console.error(err);
    return null;
  }
}

// handleError

export function handleError(
  err: any,
  state: AppContextState,
  navigate: NavigateFunction,
): void {
  if (typeof err === "string") {
    state.setError(err as AppError);
    if (err === AppError.Unauthorized) {
      removeToken(state);
      navigate("/");
    } else if (err === AppError.Forbidden) {
      navigate(PATH_FORBIDDEN);
    }
  } else {
    console.error(err);
    state.setError(AppError.Unexpected);
  }
}

// removeToken

export function removeToken(state: AppContextState): void {
  localStorage.removeItem(LOCAL_STORAGE_KEY_TOKEN);
  state.setAuth(null);
}

// spotifyRedirectUri

export function spotifyRedirectUri(): string {
  return `${window.location.origin}${PATH_AUTH}${PATH_SPOTIFY}`;
}
