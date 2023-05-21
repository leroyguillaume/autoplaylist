import { faSpinner } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { useContext, useState } from "react";
import { Button, Container, Form, Row } from "react-bootstrap";
import { useNavigate } from "react-router-dom";
import Header from "./Header";
import { HttpError, doPost } from "./api";
import { Context, Error, Info } from "./ctx";
import { BaseKind, Platform, Playlist, PlaylistRequest } from "./domain";

export default function PlaylistForm() {
  const ctx = useContext(Context);

  const [creating, setProcessing] = useState(false);
  const [validated, setValidated] = useState(false);

  const navigate = useNavigate();

  const playlist: PlaylistRequest = {
    base: {
      kind: BaseKind.Likes,
      platform: Platform.Spotify,
    },
    name: "",
  };

  const handleSubmit = async (event: any) => {
    event.preventDefault();
    event.stopPropagation();
    setValidated(true);
    const valid = event.currentTarget.checkValidity();

    if (valid) {
      setProcessing(true);
      doPost<Playlist>("playlist", playlist, ctx)
        .then((_resp) => {
          ctx.setInfo(Info.PlaylistCreated);
          navigate("/home");
        })
        .catch((err) => {
          switch (err) {
            case HttpError.Unauthorized:
              navigate("/");
              break;
            case HttpError.Conflict:
              ctx.setError(Error.PlaylistAlreadyExists);
              break;
            default:
              ctx.setError(Error.Unexpected);
              break;
          }
        })
        .finally(() => {
          setProcessing(false);
        });
    }
  };

  let submitBtn;
  if (creating) {
    submitBtn = (
      <Button variant="primary" type="submit" disabled={true}>
        <FontAwesomeIcon icon={faSpinner} className="inline" spin />
        Creating...
      </Button>
    );
  } else {
    submitBtn = (
      <Button variant="primary" type="submit">
        Create
      </Button>
    );
  }

  return (
    <>
      <Header />
      <Container>
        <Row>
          <h3>New playlist</h3>
          <Form onSubmit={handleSubmit} noValidate validated={validated}>
            <Form.Group>
              <Form.Label>Name</Form.Label>
              <Form.Control
                max="50"
                required
                defaultValue={playlist.name}
                onChange={(event) => (playlist.name = event.target.value)}
              />
            </Form.Group>
            <Form.Group>
              <Form.Label>Base</Form.Label>
              <Form.Select
                defaultValue={playlist.base.kind}
                onChange={(event) =>
                  (playlist.base.kind = event.target.value as BaseKind)
                }
              >
                <option value={BaseKind.Likes}>Likes</option>
              </Form.Select>
            </Form.Group>
            <div className="col-12 text-end">{submitBtn}</div>
          </Form>
        </Row>
      </Container>
    </>
  );
}
