import { faSpotify } from "@fortawesome/free-brands-svg-icons";
import { faSpinner } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import jwt_decode from "jwt-decode";
import { useEffect, useState } from "react";
import { Container, Row } from "react-bootstrap";
import { useNavigate } from "react-router-dom";
import Alert from "./Alert";
import "./LogIn.scss";
import { JWT_LOCAL_STORAGE_KEY } from "./api";
import logo from "./logo.webp";

export default function LogIn() {
  const [redirecting, setRedirecting] = useState(false);

  const navigate = useNavigate();

  useEffect(() => {
    const jwt = localStorage.getItem(JWT_LOCAL_STORAGE_KEY);
    if (jwt !== null) {
      const jwt_decoded: any = jwt_decode(jwt);
      const now = Math.floor(Date.now() / 1000);
      if (now < jwt_decoded.exp) {
        navigate("/home");
      }
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
      <Container className="text-center v-offset">
        <Row>
          <div className="logo">
            <img src={logo} />
          </div>
          <h1 className="title">AutoPlaylist</h1>
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
