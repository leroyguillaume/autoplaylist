import { Error } from "./ctx";

export const JWT_LOCAL_STORAGE_KEY = "jwt";

export function post<T>(path: string, body: any): Promise<T> {
  return api("POST", path, body);
}

function api<T>(method: string, path: string, body: any | null): Promise<T> {
  let headers: any = {
    "Content-Type": "application/json",
  };
  let jwt = window.localStorage.getItem(JWT_LOCAL_STORAGE_KEY);
  if (jwt !== null) {
    headers["Authorization"] = `Bearer ${jwt}`;
  }
  return fetch(`${process.env.REACT_APP_API_URL}/${path}`, {
    method,
    headers,
    body: body !== null ? JSON.stringify(body) : null,
    mode: "cors",
  })
    .catch((err) => {
      console.error(err);
      return Promise.reject(Error.Unexpected);
    })
    .then((resp) => {
      if (resp.status === 401) {
        return Promise.reject(Error.Unauthorized);
      } else if (200 <= resp.status && resp.status < 300) {
        return resp.json();
      } else {
        return Promise.reject(Error.Unexpected);
      }
    });
}
