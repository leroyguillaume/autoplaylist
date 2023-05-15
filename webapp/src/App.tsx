import { faGithub } from "@fortawesome/free-brands-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { useState } from "react";
import { RouterProvider, createBrowserRouter } from "react-router-dom";
import "./App.scss";
import ErrorPage from "./Error";
import Home from "./Home";
import LogIn from "./LogIn";
import SpotifyAuth from "./SpotifyAuth";
import { Context, ContextData, Error } from "./ctx";

export default function App() {
  const [error, setError] = useState<Error | null>(null);
  const ctx: ContextData = {
    error: error,
    setError,
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
