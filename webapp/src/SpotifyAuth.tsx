import { faSpinner } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { useContext, useEffect } from "react";
import { Container, Row } from "react-bootstrap";
import { useNavigate, useSearchParams } from "react-router-dom";
import { JWT_LOCAL_STORAGE_KEY, doPost } from "./api";
import { Context, Error, loadAuthenticatedUser } from "./ctx";

export default function SpotifyAuth() {
  const ctx = useContext(Context);

  const navigate = useNavigate();
  const [params] = useSearchParams();

  useEffect(() => {
    (async function auth() {
      const code = params.get("code");
      if (code === null) {
        navigate("/");
      } else {
        doPost<{ jwt: string }>("auth/spotify", { code }, ctx)
          .then((resp) => {
            window.localStorage.setItem(JWT_LOCAL_STORAGE_KEY, resp.jwt);
            ctx.setAuthUser(loadAuthenticatedUser());
            navigate("/home");
          })
          .catch(() => {
            ctx.setError(Error.Unexpected);
            navigate("/");
          });
      }
    })();
  }, []);

  return (
    <>
      <Container className="v-offset">
        <Row>
          <div className="text-center">
            <FontAwesomeIcon className="inline" icon={faSpinner} spin />
            Authentication in progress
          </div>
        </Row>
      </Container>
    </>
  );
}
