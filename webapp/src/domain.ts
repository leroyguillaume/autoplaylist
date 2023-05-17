export interface Base {
  creationDate: Date;
  id: string;
  kind: BaseKind;
  platform: Platform;
}

export interface BaseRequest {
  kind: BaseKind;
  platform: Platform;
}

export enum BaseKind {
  Likes = "likes",
}

export enum Grouping {
  Decades = "decades",
}

export enum Platform {
  Spotify = "spotify",
}

export interface Query {
  base: BaseRequest;
  creationDate: Date;
  grouping: Grouping;
  id: string;
  namePrefix: string;
}

export interface QueryRequest {
  base: BaseRequest;
  grouping: Grouping;
  namePrefix: string;
}
