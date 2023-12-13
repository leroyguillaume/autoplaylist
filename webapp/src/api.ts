import { AppError, LOCAL_STORAGE_KEY_TOKEN, PATH_PLAYLIST, PATH_SRC } from ".";
import { config, spotifyRedirectUri } from "./utils";

// Consts - Paths

export const API_PATH_AUTH = "/auth";
export const API_PATH_ME = "/me";
export const API_PATH_PLAYLIST = "/playlist";
export const API_PATH_REFRESH = "/refresh";
export const API_PATH_SPOTIFY = "/spotify";
export const API_PATH_SRC = "/source";
export const API_PATH_SYNC = "/sync";
export const API_PATH_TOKEN = "/token";
export const API_PATH_TRACK = "/track";
export const API_PATH_USR = "/user";

// Types

export type PendingSynchronization = "pending";

export type Predicate =
  | AndPredicate
  | ArtistsAreExactlyPredicate
  | ArtistsArePredicate
  | OrPredicate
  | YearIsPredicate
  | YearIsBetweenPredicate;

export type Synchronization =
  | AbortedSynchronization
  | FailedSynchronization
  | PendingSynchronization
  | RunningSynchronization
  | SucceededSynchronization;

// AbortedSynchronization

export interface AbortedSynchronization {
  aborted: {
    end: string;
    start: string;
  };
}

// Album

export interface Album {
  compil: boolean;
  name: string;
}

// AndPredicate

export interface AndPredicate {
  and: [Predicate, Predicate];
}

// ArtistsAreExactlyPredicate

export interface ArtistsAreExactlyPredicate {
  artistsAreExactly: string[];
}

// ArtistsArePredicate

export interface ArtistsArePredicate {
  artistsAre: string[];
}

// CreatePlaylistRequest

export interface CreatePlaylistRequest {
  name: string;
  predicate: Predicate;
  src: SourceKind;
}

// Credentials

export interface Credentials {
  spotify?: SpotifyCredentials;
}

// FailedSynchronization

export interface FailedSynchronization {
  failed: {
    details?: string;
    end: string;
    start: string;
  };
}

// Jwt

export interface Jwt {
  jwt: string;
}

// OrPredicate

export interface OrPredicate {
  or: [Predicate, Predicate];
}

// Page

export interface Page<ITEM> {
  first: boolean;
  items: ITEM[];
  last: boolean;
  req: PageRequest;
  total: number;
}

// PageRequest

export interface PageRequest {
  limit: number;
  offset: number;
}

// Platform

export enum Platform {
  Spotify = "spotify",
}

// PlatformPlaylist

export interface PlatformPlaylist {
  id: string;
  name: string;
}

// Playlist

export interface Playlist {
  creation: string;
  id: string;
  name: string;
  predicate: Predicate;
  src: Source;
  sync: Synchronization;
  tgt: Target;
}

// Role

export enum Role {
  Admin = "admin",
  User = "user",
}

// RunningSynchronization

export interface RunningSynchronization {
  running: string;
}

// SourceKind

export interface SourceKind {
  spotify: "savedTracks" | SpotifyPlaylistSourceKind;
}

// Source

export interface Source {
  creation: string;
  id: string;
  kind: SourceKind;
  owner: User;
  sync: Synchronization;
}

// SpotifyCredentials

export interface SpotifyCredentials {
  email: string;
  id: string;
}

// SpotifyPlaylistSourceKind

export interface SpotifyPlaylistSourceKind {
  playlist: string;
}

// SucceededSynchronization

export interface SucceededSynchronization {
  succeeded: { end: string; start: string };
}

// Target

export interface Target {
  spotify: string;
}

// Track

export interface Track {
  album: Album;
  artists: string[];
  creation: string;
  id: string;
  platform: Platform;
  platformId: string;
  title: string;
  year: number;
}

// UpdatePlaylistRequest

export interface UpdatePlaylistRequest {
  name: string;
  predicate: Predicate;
}

// UpdateTrackRequest

export interface UpdateTrackRequest {
  album: Album;
  artists: string[];
  title: string;
  year: number;
}

// UpdateUserRequest

export interface UpdateUserRequest {
  role: Role;
}

// User

export interface User {
  creation: string;
  creds: Credentials;
  id: string;
  role: Role;
}

// YearIsPredicate

export interface YearIsPredicate {
  yearIs: number;
}

// YearIsBetweenPredicate

export interface YearIsBetweenPredicate {
  yearIsBetween: [number, number];
}

// authenticateViaSpotify

export async function authenticateViaSpotify(code: string): Promise<Jwt> {
  return await config()
    .then(async (cfg) => {
      const params = new URLSearchParams({
        code,
        redirect_uri: spotifyRedirectUri(),
      });
      return await fetch(
        `${
          cfg.apiUrl
        }${API_PATH_AUTH}${API_PATH_SPOTIFY}${API_PATH_TOKEN}?${params.toString()}`,
        {
          method: "GET",
          mode: "cors",
        },
      );
    })
    .catch(async (err) => {
      console.error(err);
      return await Promise.reject(AppError.Unexpected);
    })
    .then(parseJsonResponse<Jwt>);
}

// createPlaylist

export async function createPlaylist(
  creation: CreatePlaylistRequest,
): Promise<Playlist> {
  return await create<Playlist>(`${API_PATH_PLAYLIST}`, creation);
}

// deletePlaylist

export async function deletePlaylist(id: string): Promise<void> {
  await deleteById(API_PATH_PLAYLIST, id);
}

// deleteTrack

export async function deleteTrack(id: string): Promise<void> {
  await deleteById(API_PATH_TRACK, id);
}

// deleteUser

export async function deleteUser(id: string): Promise<void> {
  await deleteById(API_PATH_USR, id);
}

// playlistById

export async function playlistById(id: string): Promise<Playlist> {
  return await byId<Playlist>(API_PATH_PLAYLIST, id);
}

// playlists

export async function playlists(
  req: PageRequest,
  q?: string,
): Promise<Page<Playlist>> {
  return await list<Playlist>(API_PATH_PLAYLIST, req, q);
}

// predicateIsAnd

export function predicateIsAnd(
  predicate: Predicate,
): predicate is AndPredicate {
  return typeof predicate === "object" && "and" in predicate;
}

// predicateIsArtistsAre

export function predicateIsArtistsAre(
  predicate: Predicate,
): predicate is ArtistsArePredicate {
  return typeof predicate === "object" && "artistsAre" in predicate;
}

// predicateIsArtistsAreExactly

export function predicateIsArtistsAreExactly(
  predicate: Predicate,
): predicate is ArtistsAreExactlyPredicate {
  return typeof predicate === "object" && "artistsAreExactly" in predicate;
}

// predicateIsOr

export function predicateIsOr(predicate: Predicate): predicate is OrPredicate {
  return typeof predicate === "object" && "or" in predicate;
}

// predicateIsYearIs

export function predicateIsYearIs(
  predicate: Predicate,
): predicate is YearIsPredicate {
  return typeof predicate === "object" && "yearIs" in predicate;
}

// predicateIsYearIsBetween

export function predicateIsYearIsBetween(
  predicate: Predicate,
): predicate is YearIsBetweenPredicate {
  return typeof predicate === "object" && "yearIsBetween" in predicate;
}

// refreshUserSpotifyPlaylists

export async function refreshUserSpotifyPlaylists(id: string): Promise<void> {
  await command(
    `${API_PATH_USR}/${id}${API_PATH_PLAYLIST}${API_PATH_SPOTIFY}${API_PATH_REFRESH}`,
  );
}

// sources

export async function sources(req: PageRequest): Promise<Page<Source>> {
  return await list<Source>(API_PATH_SRC, req);
}

// startPlaylistSynchronization

export async function startPlaylistSynchronization(id: string): Promise<void> {
  await command(`${API_PATH_PLAYLIST}/${id}${API_PATH_SYNC}`);
}

// startSourceSynchronization

export async function startSourceSynchronization(id: string): Promise<void> {
  await command(`${API_PATH_SRC}/${id}${API_PATH_SYNC}`);
}

// synchronizationIsAborted

export function synchronizationIsAborted(
  sync: Synchronization,
): sync is AbortedSynchronization {
  return typeof sync === "object" && "aborted" in sync;
}

// synchronizationIsFailed

export function synchronizationIsFailed(
  sync: Synchronization,
): sync is FailedSynchronization {
  return typeof sync === "object" && "failed" in sync;
}

// synchronizationIsRunning

export function synchronizationIsRunning(
  sync: Synchronization,
): sync is RunningSynchronization {
  return typeof sync === "object" && "running" in sync;
}

// synchronizationIsSucceeded

export function synchronizationIsSucceeded(
  sync: Synchronization,
): sync is SucceededSynchronization {
  return typeof sync === "object" && "succeeded" in sync;
}

// trackById

export async function trackById(id: string): Promise<Track> {
  return await byId<Track>(API_PATH_TRACK, id);
}

// tracks

export async function tracks(
  req: PageRequest,
  q?: string,
): Promise<Page<Track>> {
  return await list<Track>(API_PATH_TRACK, req, q);
}

// updatePlaylist

export async function updatePlaylist(
  id: string,
  req: UpdatePlaylistRequest,
): Promise<Playlist> {
  return await update<Playlist>(API_PATH_PLAYLIST, id, req);
}

// updateTrack

export async function updateTrack(
  id: string,
  req: UpdateTrackRequest,
): Promise<Track> {
  return await update<Track>(API_PATH_TRACK, id, req);
}

// updateUser

export async function updateUser(
  id: string,
  req: UpdateUserRequest,
): Promise<User> {
  return await update<User>(API_PATH_USR, id, req);
}

// userById

export async function userById(id: string): Promise<User> {
  return await byId<User>(API_PATH_USR, id);
}

// userPlaylists

export async function userPlaylists(
  id: string,
  req: PageRequest,
  q?: string,
): Promise<Page<Playlist>> {
  return await list<Playlist>(`${API_PATH_USR}/${id}${PATH_PLAYLIST}`, req, q);
}

// userSources

export async function userSources(
  id: string,
  req: PageRequest,
): Promise<Page<Source>> {
  return await list<Source>(`${API_PATH_USR}/${id}${PATH_SRC}`, req);
}

// userSpotifyPlaylists

export async function userSpotifyPlaylists(
  id: string,
  req: PageRequest,
  q?: string,
): Promise<Page<PlatformPlaylist>> {
  return await list<PlatformPlaylist>(
    `${API_PATH_USR}/${id}${API_PATH_PLAYLIST}${API_PATH_SPOTIFY}`,
    req,
    q,
  );
}

// users

export async function users(req: PageRequest, q?: string): Promise<Page<User>> {
  return await list<User>(API_PATH_USR, req, q);
}

// byId

async function byId<T>(path: string, id: string): Promise<T> {
  return await config()
    .then(async (cfg) => {
      const token = localStorage.getItem(LOCAL_STORAGE_KEY_TOKEN);
      return await fetch(`${cfg.apiUrl}${path}/${id}`, {
        headers: { Authorization: `Bearer ${token}` },
        method: "GET",
        mode: "cors",
      });
    })
    .then(parseJsonResponse<T>);
}

// command

async function command(path: string): Promise<void> {
  await config()
    .then(async (cfg) => {
      const token = localStorage.getItem(LOCAL_STORAGE_KEY_TOKEN);
      return await fetch(`${cfg.apiUrl}${path}`, {
        headers: { Authorization: `Bearer ${token}` },
        method: "PUT",
        mode: "cors",
      });
    })
    .catch(async (err) => {
      console.error(err);
      return await Promise.reject(AppError.Unexpected);
    })
    .then(mapError);
}

// create

async function create<T>(path: string, creation: any): Promise<T> {
  return await config()
    .then(async (cfg) => {
      const token = localStorage.getItem(LOCAL_STORAGE_KEY_TOKEN);
      return await fetch(`${cfg.apiUrl}${path}`, {
        body: JSON.stringify(creation),
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        method: "POST",
        mode: "cors",
      });
    })
    .catch(async (err) => {
      console.error(err);
      return await Promise.reject(AppError.Unexpected);
    })
    .then(parseJsonResponse<T>);
}

// deleteById

async function deleteById(path: string, id: string): Promise<void> {
  await config()
    .then(async (cfg) => {
      const token = localStorage.getItem(LOCAL_STORAGE_KEY_TOKEN);
      return await fetch(`${cfg.apiUrl}${path}/${id}`, {
        headers: { Authorization: `Bearer ${token}` },
        method: "DELETE",
        mode: "cors",
      });
    })
    .catch(async (err) => {
      console.error(err);
      return await Promise.reject(AppError.Unexpected);
    })
    .then(mapError);
}

// list

async function list<T>(
  path: string,
  req: PageRequest,
  q?: string,
): Promise<Page<T>> {
  return await config()
    .then(async (cfg) => {
      const params = new URLSearchParams({
        limit: req.limit.toString(),
        offset: req.offset.toString(),
        q: q?.toString() ?? "",
      });
      const token = localStorage.getItem(LOCAL_STORAGE_KEY_TOKEN);
      return await fetch(`${cfg.apiUrl}${path}?${params.toString()}`, {
        headers: { Authorization: `Bearer ${token}` },
        method: "GET",
        mode: "cors",
      });
    })
    .then(parseJsonResponse<Page<T>>);
}

// mapError

async function mapError(resp: Response): Promise<Response> {
  if (resp.status === 401) {
    return await Promise.reject(AppError.Unauthorized);
  }
  if (resp.status === 403) {
    return await Promise.reject(AppError.Forbidden);
  }
  if (resp.status < 200 || resp.status >= 300) {
    console.error(resp);
    return await Promise.reject(AppError.Unexpected);
  }
  return resp;
}

// parseJsonResponse

async function parseJsonResponse<T>(resp: Response): Promise<T> {
  return await mapError(resp).then(async (resp) => await resp.json());
}

// update

async function update<T>(path: string, id: string, body: any): Promise<T> {
  return await config()
    .then(async (cfg) => {
      const token = localStorage.getItem(LOCAL_STORAGE_KEY_TOKEN);
      return await fetch(`${cfg.apiUrl}${path}/${id}`, {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        method: "PUT",
        mode: "cors",
        body: JSON.stringify(body),
      });
    })
    .catch(async (err) => {
      console.error(err);
      return await Promise.reject(AppError.Unexpected);
    })
    .then(parseJsonResponse<T>);
}
