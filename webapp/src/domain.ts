export interface Base {
  creationDate: string;
  id: string;
  kind: BaseKind;
  platform: Platform;
  sync: Sync | null;
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
  creationDate: string;
  id: string;
  name: string;
}

export interface PlaylistFilter {
  kind: PlaylistFilterKind;
  op: PlaylistFilterOperator;
  value: string;
}

export enum PlaylistFilterKind {
  Artist = "artist",
}

export enum PlaylistFilterOperator {
  Is = "is",
}

export interface PlaylistRequest {
  base: BaseRequest;
  filters: any[];
  name: string;
}

export enum Role {
  Admin = "admin",
  User = "user",
}

export interface Sync {
  lastErrMsg: string | null;
  lastStartDate: string;
  lastSuccessDate: string | null;
  state: SyncState;
}

export enum SyncState {
  Aborted = "aborted",
  Failed = "failed",
  Running = "running",
  Succeeded = "succeeded",
}
