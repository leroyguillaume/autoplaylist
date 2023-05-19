import { faGithub } from "@fortawesome/free-brands-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { useState } from "react";
import { RouterProvider, createBrowserRouter } from "react-router-dom";
import "./App.scss";
import ErrorPage from "./Error";
import Home from "./Home";
import LogIn from "./LogIn";
import QueryForm from "./QueryForm";
import SpotifyAuth from "./SpotifyAuth";
import { JWT_LOCAL_STORAGE_KEY } from "./api";
import {
  AuthenticatedUser,
  Context,
  ContextData,
  Error,
  Info,
  decodeJwt,
} from "./ctx";

export default function App() {
  const jwt = localStorage.getItem(JWT_LOCAL_STORAGE_KEY);
  const [authUser, setAuthUser] = useState<AuthenticatedUser | null>(
    decodeJwt(jwt)
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
      path: "/query",
      element: <QueryForm />,
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
