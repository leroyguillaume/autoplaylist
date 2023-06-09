import { NavigateFunction } from "react-router-dom";
import { ContextData, Error } from "./ctx";

export const JWT_LOCAL_STORAGE_KEY = "jwt";

export enum HttpError {
  Conflict,
  Unauthorized,
  Unexpected,
}

export function doDelete(path: string, ctx: ContextData): Promise<void> {
  return callApi("DELETE", path, {}, null, ctx);
}

export function doGet<T>(
  path: string,
  params: any,
  ctx: ContextData
): Promise<T> {
  return callApi("GET", path, params, null, ctx);
}

export function doPost<T>(
  path: string,
  body: any,
  ctx: ContextData
): Promise<T> {
  return callApi("POST", path, {}, body, ctx);
}

export function doPut<T>(
  path: string,
  body: any | null,
  ctx: ContextData
): Promise<T> {
  return callApi("PUT", path, {}, body, ctx);
}

export function handleCommonErrors(
  err: HttpError,
  ctx: ContextData,
  navigate: NavigateFunction
) {
  if (err === HttpError.Unauthorized) {
    navigate("/");
  } else {
    ctx.setError(Error.Unexpected);
  }
}

function callApi<T>(
  method: string,
  path: string,
  params: any,
  body: any | null,
  ctx: ContextData
): Promise<T> {
  let headers: any = {
    "Content-Type": "application/json",
  };
  let jwt = window.localStorage.getItem(JWT_LOCAL_STORAGE_KEY);
  if (jwt !== null) {
    headers["Authorization"] = `Bearer ${jwt}`;
  }
  const queryParams = new URLSearchParams(params);
  return fetch(`${process.env.REACT_APP_API_URL}/${path}?${queryParams}`, {
    method,
    headers,
    body: body !== null ? JSON.stringify(body) : null,
    mode: "cors",
  })
    .catch((err) => {
      console.error(err);
      return Promise.reject(HttpError.Unexpected);
    })
    .then((resp) => {
      if (resp.status === 401) {
        ctx.setAuthUser(null);
        localStorage.removeItem(JWT_LOCAL_STORAGE_KEY);
        ctx.setError(Error.Unauthorized);
        return Promise.reject(HttpError.Unauthorized);
      } else if (resp.status === 409) {
        return Promise.reject(HttpError.Conflict);
      } else if (resp.status === 204) {
        return;
      } else if (200 <= resp.status && resp.status < 300) {
        return resp.json();
      } else {
        return Promise.reject(HttpError.Unexpected);
      }
    });
}
