import React, { useContext, useEffect, useState } from "react";
import { Col, Container, Row } from "react-bootstrap";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faSpotify } from "@fortawesome/free-brands-svg-icons";
import { API_PATH_AUTH, API_PATH_SPOTIFY } from "./api";
import {
  AppContext,
  type AppError,
  LOCAL_STORAGE_KEY_TOKEN,
  PATH_PLAYLIST,
} from ".";
import { t } from "i18next";
import { useNavigate } from "react-router-dom";
import Alerts from "./Alerts";
import { config, decodeToken, spotifyRedirectUri } from "./utils";
import { faSpinner } from "@fortawesome/free-solid-svg-icons";

function AuthPage(): JSX.Element {
  const state = useContext(AppContext);

  const navigate = useNavigate();

  const [spotifyAuthorizeUrl, setSpotifyAuthorizeUrl] = useState<string | null>(
    null,
  );

  useEffect(() => {
    const token = localStorage.getItem(LOCAL_STORAGE_KEY_TOKEN);
    if (token !== null) {
      const auth = decodeToken(token);
      if (auth === null) {
        localStorage.removeItem(LOCAL_STORAGE_KEY_TOKEN);
      } else {
        navigate(PATH_PLAYLIST);
      }
    }
    void config()
      .then((cfg) => {
        const spotifyAuthorizeUrlParams = new URLSearchParams({
          redirect_uri: spotifyRedirectUri(),
        });
        setSpotifyAuthorizeUrl(
          `${
            cfg.apiUrl
          }${API_PATH_AUTH}${API_PATH_SPOTIFY}?${spotifyAuthorizeUrlParams.toString()}`,
        );
      })
      .catch((err: AppError) => {
        state.setError(err);
      });
  });

  let div;
  if (spotifyAuthorizeUrl === null) {
    div = (
      <Row>
        <Col>
          <FontAwesomeIcon icon={faSpinner} spin />
        </Col>
      </Row>
    );
  } else {
    div = (
      <Row>
        <Col>
          <a className="btn btn-primary" href={spotifyAuthorizeUrl}>
            <FontAwesomeIcon icon={faSpotify} className="inline-icon" />
            {t("label.spotify-login")}
          </a>
        </Col>
      </Row>
    );
  }

  return (
    <>
      <Alerts />
      <Container className="text-center">
        <Row>
          <Col>
            <img src="/logo.png" alt="logo" />
          </Col>
        </Row>
        <Row>
          <Col>
            <p>{t("paragraph.description")}</p>
          </Col>
        </Row>
        {div}
      </Container>
      <Container></Container>
    </>
  );
}

export default AuthPage;
