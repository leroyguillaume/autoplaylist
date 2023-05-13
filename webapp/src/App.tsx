import { faGithub } from "@fortawesome/free-brands-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { RouterProvider, createBrowserRouter } from "react-router-dom";
import "./App.scss";
import ErrorPage from "./ErrorPage";
import LogIn from "./LogIn";

export default function App() {
  const router = createBrowserRouter([
    {
      path: "/",
      element: <LogIn />,
      errorElement: <ErrorPage />,
    },
  ]);

  return (
    <>
      <RouterProvider router={router} />
      <footer>
        <a href="https://github.com/leroyguillaume/autoplaylist">
          <FontAwesomeIcon icon={faGithub} size="2x" />
        </a>
      </footer>
    </>
  );
}
