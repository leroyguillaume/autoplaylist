import { faGithub } from "@fortawesome/free-brands-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { useState } from "react";
import { RouterProvider, createBrowserRouter } from "react-router-dom";
import ErrorPage from "./Error";
import Home from "./Home";
import LogIn from "./LogIn";
import PlaylistForm from "./PlaylistForm";
import SpotifyAuth from "./SpotifyAuth";
import SyncSummary from "./SyncSummary";
import {
  AuthenticatedUser,
  Context,
  ContextData,
  Error,
  Info,
  loadAuthenticatedUser,
} from "./ctx";

export default function App() {
  const [authUser, setAuthUser] = useState<AuthenticatedUser | null>(
    loadAuthenticatedUser()
  );
  const [error, setError] = useState<Error | null>(null);
  const [info, setInfo] = useState<Info | null>(null);

  const ctx: ContextData = {
    authUser,
    error,
    info,
    setAuthUser,
    setError,
    setInfo,
  };

  const router = createBrowserRouter([
    {
      path: "/",
      element: <LogIn />,
      errorElement: <ErrorPage />,
    },
    {
      path: "/admin/sync",
      element: <SyncSummary />,
      errorElement: <ErrorPage />,
    },
    {
      path: "/auth/spotify",
      element: <SpotifyAuth />,
      errorElement: <ErrorPage />,
    },
    {
      path: "/home",
      element: <Home />,
      errorElement: <ErrorPage />,
    },
    {
      path: "/playlist",
      element: <PlaylistForm />,
      errorElement: <ErrorPage />,
    },
  ]);

  return (
    <>
      <Context.Provider value={ctx}>
        <RouterProvider router={router} />
        <footer>
          <a href="https://github.com/leroyguillaume/autoplaylist">
            <FontAwesomeIcon icon={faGithub} size="2x" />
          </a>
        </footer>
      </Context.Provider>
    </>
  );
}
