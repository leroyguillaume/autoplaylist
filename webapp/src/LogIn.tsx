import { faSpotify } from "@fortawesome/free-brands-svg-icons";
import { faSpinner } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { useContext, useEffect, useState } from "react";
import { Container, Row } from "react-bootstrap";
import { useNavigate } from "react-router-dom";
import Alert from "./Alert";
import { Context } from "./ctx";
import logo from "./logo.webp";

export default function LogIn() {
  const ctx = useContext(Context);
  const [redirecting, setRedirecting] = useState(false);

  const navigate = useNavigate();

  useEffect(() => {
    if (ctx.authUser !== null) {
      navigate("/home");
    }
  });

  let btnChild;
  if (redirecting) {
    btnChild = (
      <>
        <FontAwesomeIcon icon={faSpinner} spin />
      </>
    );
  } else {
    btnChild = (
      <>
        <FontAwesomeIcon className="inline" icon={faSpotify} />
        Log-in with Spotify
      </>
    );
  }

  return (
    <>
      <Alert></Alert>
      <Container className="text-center">
        <Row>
          <div className="login-logo">
            <img src={logo} />
          </div>
          <h1 className="login-brand">AutoPlaylist</h1>
          <div>
            <a
              className="btn btn-primary"
              href={`${process.env.REACT_APP_API_URL}/auth/spotify`}
              onClick={() => setRedirecting(true)}
            >
              {btnChild}
            </a>
          </div>
        </Row>
      </Container>
    </>
  );
}
