import { faSpinner } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { useContext, useState } from "react";
import { Button, Container, Form, Row } from "react-bootstrap";
import { useNavigate } from "react-router-dom";
import Header from "./Header";
import { HttpError, doPost } from "./api";
import { Context, Error, Info } from "./ctx";
import { BaseKind, Grouping, Platform, Query, QueryRequest } from "./domain";

export default function QueryForm() {
  const ctx = useContext(Context);

  const [creating, setProcessing] = useState(false);
  const [validated, setValidated] = useState(false);

  const navigate = useNavigate();

  const query: QueryRequest = {
    base: {
      kind: BaseKind.Likes,
      platform: Platform.Spotify,
    },
    grouping: Grouping.Decades,
    namePrefix: "",
  };

  const handleSubmit = async (event: any) => {
    setProcessing(true);
    event.preventDefault();
    event.stopPropagation();
    setValidated(true);
    const valid = event.currentTarget.checkValidity();

    if (valid) {
      doPost<Query>("query", query, ctx)
        .then((_resp) => {
          ctx.setInfo(Info.QueryCreated);
          navigate("/home");
        })
        .catch((err) => {
          switch (err) {
            case HttpError.Unauthorized:
              navigate("/");
              break;
            case HttpError.Conflict:
              ctx.setError(Error.QueryAlreadyExists);
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
          <h3>New query</h3>
          <Form onSubmit={handleSubmit} noValidate validated={validated}>
            <Form.Group>
              <Form.Label>Base</Form.Label>
              <Form.Select
                defaultValue={query.base.kind}
                onChange={(event) =>
                  (query.base.kind = event.target.value as BaseKind)
                }
              >
                <option value={BaseKind.Likes}>Likes</option>
              </Form.Select>
            </Form.Group>
            <Form.Group>
              <Form.Label>Group playlists by</Form.Label>
              <Form.Select
                defaultValue={query.grouping}
                onChange={(event) =>
                  (query.grouping = event.target.value as Grouping)
                }
              >
                <option value={Grouping.Decades}>Decades</option>
              </Form.Select>
            </Form.Group>
            <Form.Group>
              <Form.Label>Prefix of playlist names</Form.Label>
              <Form.Control
                max="50"
                defaultValue={query.namePrefix}
                onChange={(event) => (query.namePrefix = event.target.value)}
              />
            </Form.Group>
            <div className="col-12 text-end">{submitBtn}</div>
          </Form>
        </Row>
      </Container>
    </>
  );
}
