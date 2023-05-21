export interface Base {
  creationDate: string;
  id: string;
  kind: BaseKind;
  platform: Platform;
  sync: Sync;
}

export interface BaseRequest {
  kind: BaseKind;
  platform: Platform;
}

export enum BaseKind {
  Likes = "likes",
}

export interface Page<T> {
  content: T[];
  total: number;
}

export enum Platform {
  Spotify = "spotify",
}

export interface Playlist {
  base: Base;
  creationDate: string;
  id: string;
  name: string;
}

export interface PlaylistRequest {
  base: BaseRequest;
  name: string;
}

export enum Role {
  Admin = "admin",
  User = "user",
}

export interface Sync {
  lastErrMsg: string | null;
  lastStartDate: string | null;
  lastSuccessDate: string | null;
  state: SyncState | null;
}

export enum SyncState {
  Aborted = "aborted",
  Failed = "failed",
  Running = "running",
  Succeeded = "succeeded",
}
