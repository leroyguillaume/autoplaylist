export const JWT_LOCAL_STORAGE_KEY = "jwt";

export enum HttpError {
  Conflict,
  Unauthorized,
  Unexpected,
}

export function get<T>(path: string, query: any): Promise<T> {
  return api("GET", path, query, null);
}

export function post<T>(path: string, body: any): Promise<T> {
  return api("POST", path, {}, body);
}

function api<T>(
  method: string,
  path: string,
  query: any,
  body: any | null
): Promise<T> {
  let headers: any = {
    "Content-Type": "application/json",
  };
  let jwt = window.localStorage.getItem(JWT_LOCAL_STORAGE_KEY);
  if (jwt !== null) {
    headers["Authorization"] = `Bearer ${jwt}`;
  }
  const params = new URLSearchParams(query);
  return fetch(`${process.env.REACT_APP_API_URL}/${path}?${params}`, {
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
        return Promise.reject(HttpError.Unauthorized);
      } else if (resp.status === 409) {
        return Promise.reject(HttpError.Conflict);
      } else if (200 <= resp.status && resp.status < 300) {
        return resp.json();
      } else {
        return Promise.reject(HttpError.Unexpected);
      }
    });
}
