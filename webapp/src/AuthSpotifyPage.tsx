import { faSpinner } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { Col, Container, Row } from "react-bootstrap";
import React, { useContext, useEffect } from "react";
import { authenticateViaSpotify } from "./api";
import { useNavigate, useSearchParams } from "react-router-dom";
import {
  AppContext,
  type AppError,
  LOCAL_STORAGE_KEY_TOKEN,
  PATH_PLAYLIST,
} from ".";
import Alerts from "./Alerts";
import { decodeToken } from "./utils";
import { t } from "i18next";

function AuthSpotifyPage(): JSX.Element {
  const state = useContext(AppContext);
  const navigate = useNavigate();
  const [params] = useSearchParams();

  useEffect(() => {
    const authenticate = async (): Promise<void> => {
      const code = params.get("code");
      if (code === null) {
        navigate("/");
      } else {
        await authenticateViaSpotify(code)
          .then((resp) => {
            const auth = decodeToken(resp.jwt);
            if (auth === null) {
              navigate("/");
            } else {
              localStorage.setItem(LOCAL_STORAGE_KEY_TOKEN, resp.jwt);
              state.setAuth(auth);
              navigate(PATH_PLAYLIST);
            }
          })
          .catch((err: AppError) => {
            state.setError(err);
          });
      }
    };
    // eslint-disable-next-line @typescript-eslint/no-floating-promises
    authenticate();
  }, []);

  return (
    <>
      <Alerts />
      <Container>
        <Row>
          <Col>
            <p>
              <FontAwesomeIcon icon={faSpinner} spin className="inline-icon" />
              {t("label.authenticating")}
              {t("punctuation.elipsis")}
            </p>
          </Col>
        </Row>
      </Container>
    </>
  );
}

export default AuthSpotifyPage;
