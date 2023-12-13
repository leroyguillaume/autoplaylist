import React, { createContext, useState } from "react";
import ReactDOM from "react-dom/client";
import "./index.scss";
import reportWebVitals from "./reportWebVitals";
import AuthPage from "./AuthPage";
import { createBrowserRouter, RouterProvider } from "react-router-dom";
import AuthSpotifyPage from "./AuthSpotifyPage";
import { initReactI18next } from "react-i18next";
import i18n from "i18next";
import i18nEn from "./i18n/en.json";
import MyPlaylistsPage from "./MyPlaylistsPage";
import CreatePlaylistPage from "./CreatePlaylistPage";
import { type Role } from "./api";
import { decodeToken } from "./utils";
import AdminPlaylistsPage from "./AdminPlaylistsPage";
import AdminUserPage from "./AdminUserPage";
import NotFoundPage from "./NotFoundPage";
import AdminUsersPage from "./AdminUsersPage";
import ForbiddenPage from "./ForbiddenPage";
import PlaylistPage from "./PlaylistPage";
import AdminSourcesPage from "./AdminSourcesPage";
import AdminUserPlaylistsPage from "./AdminUserPlaylistsPage";
import AdminUserSourcesPage from "./AdminUserSourcesPage";
import MyAccountPage from "./MyAccountPage";
import AdminTracksPage from "./AdminTracksPage";
import AdminTrackPage from "./AdminTrackPage";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faGithub } from "@fortawesome/free-brands-svg-icons";

export const LOCAL_STORAGE_KEY_TOKEN = "token";

export const PARAM_ID = "id";
export const PARAM_PAGE = "page";
export const PARAM_Q = "q";

export const PATH_ADMIN = "/admin";
export const PATH_AUTH = "/auth";
export const PATH_FORBIDDEN = "/forbidden";
export const PATH_ME = "/me";
export const PATH_NEW = "/new";
export const PATH_NOT_FOUND = "/not-found";
export const PATH_PLAYLIST = "/playlist";
export const PATH_SPOTIFY = "/spotify";
export const PATH_SRC = "/source";
export const PATH_TRACK = "/track";
export const PATH_USR = "/user";

export const LIMIT = 10;

export enum AppError {
  Config = "config",
  Forbidden = "forbidden",
  Unexpected = "unexpected",
  Unauthorized = "unauthorized",
}

export enum AppInfo {
  PlaylistCreated = "playlist-created",
  PlaylistDeleted = "playlist-deleted",
  PlaylistSynchronizationStarted = "playlist-synchronization-started",
  PlaylistUpdated = "playlist-updated",
  SourceSynchronizationStarted = "source-synchronization-started",
  TrackDeleted = "track-deleted",
  TrackUpdated = "track-updated",
  UserDeleted = "user-deleted",
  UserUpdated = "user-updated",
}

export interface AppContextState {
  auth: Auth | null;
  err: AppError | null;
  info: AppInfo | null;
  setAuth: (auth: Auth | null) => void;
  setError: (err: AppError | null) => void;
  setInfo: (info: AppInfo | null) => void;
}

export interface Auth {
  id: string;
  role: Role;
}

export const AppContext = createContext<AppContextState>({
  auth: null,
  info: null,
  err: null,
  setAuth: () => {},
  setError: () => {},
  setInfo: () => {},
});

const router = createBrowserRouter([
  {
    path: "/",
    element: <AuthPage />,
    errorElement: <NotFoundPage />,
  },
  {
    path: `${PATH_ADMIN}${PATH_PLAYLIST}`,
    element: <AdminPlaylistsPage />,
  },
  {
    path: `${PATH_ADMIN}${PATH_SRC}`,
    element: <AdminSourcesPage />,
  },
  {
    path: `${PATH_ADMIN}${PATH_TRACK}`,
    element: <AdminTracksPage />,
  },
  {
    path: `${PATH_ADMIN}${PATH_TRACK}/:${PARAM_ID}`,
    element: <AdminTrackPage />,
  },
  {
    path: `${PATH_ADMIN}${PATH_USR}`,
    element: <AdminUsersPage />,
  },
  {
    path: `${PATH_ADMIN}${PATH_USR}/:${PARAM_ID}`,
    element: <AdminUserPage />,
  },
  {
    path: `${PATH_ADMIN}${PATH_USR}/:${PARAM_ID}${PATH_PLAYLIST}`,
    element: <AdminUserPlaylistsPage />,
  },
  {
    path: `${PATH_ADMIN}${PATH_USR}/:${PARAM_ID}${PATH_SRC}`,
    element: <AdminUserSourcesPage />,
  },
  {
    path: `${PATH_AUTH}${PATH_SPOTIFY}`,
    element: <AuthSpotifyPage />,
  },
  {
    path: PATH_FORBIDDEN,
    element: <ForbiddenPage />,
  },
  {
    path: PATH_ME,
    element: <MyAccountPage />,
  },
  {
    path: PATH_NOT_FOUND,
    element: <NotFoundPage />,
  },
  {
    path: PATH_PLAYLIST,
    element: <MyPlaylistsPage />,
  },
  {
    path: `${PATH_PLAYLIST}/:${PARAM_ID}`,
    element: <PlaylistPage />,
  },
  {
    path: `${PATH_PLAYLIST}${PATH_NEW}`,
    element: <CreatePlaylistPage />,
  },
]);

// eslint-disable-next-line @typescript-eslint/no-floating-promises
i18n.use(initReactI18next).init({
  resources: {
    en: {
      common: i18nEn,
    },
  },
  ns: ["common"],
  defaultNS: "common",
  fallbackLng: "en",
  interpolation: {
    escapeValue: false,
  },
});

const App = (): JSX.Element => {
  const jwt = localStorage.getItem(LOCAL_STORAGE_KEY_TOKEN);
  const initialAuth = jwt === null ? null : decodeToken(jwt);
  const [auth, setAuth] = useState<Auth | null>(initialAuth);
  const [err, setError] = useState<AppError | null>(null);
  const [info, setInfo] = useState<AppInfo | null>(null);

  const state = {
    auth,
    err,
    info,
    setAuth,
    setError,
    setInfo,
  };

  return (
    <>
      <AppContext.Provider value={state}>
        <RouterProvider router={router} />
      </AppContext.Provider>
      <footer className="footer">
        <a href="https://github.com/leroyguillaume/autoplaylist">
          <FontAwesomeIcon icon={faGithub} size="2xl" />
        </a>
      </footer>
    </>
  );
};

const root = ReactDOM.createRoot(
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  document.getElementById("root")!,
);
root.render(<App />);

// If you want to start measuring performance in your app, pass a function
// to log results (for example: reportWebVitals(console.log))
// or send to an analytics endpoint. Learn more: https://bit.ly/CRA-vitals
reportWebVitals();
