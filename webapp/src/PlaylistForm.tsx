import { faPlus, faSpinner, faTrash } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { useContext, useState } from "react";
import { Button, Container, Form, InputGroup, Row } from "react-bootstrap";
import { useNavigate } from "react-router-dom";
import Header from "./Header";
import { HttpError, doPost } from "./api";
import { Context, Error, Info } from "./ctx";
import {
  BaseKind,
  Platform,
  Playlist,
  PlaylistFilter,
  PlaylistFilterKind,
  PlaylistFilterOperator,
  PlaylistRequest,
} from "./domain";

export default function PlaylistForm() {
  const ctx = useContext(Context);

  const [baseKind, setBaseKind] = useState(BaseKind.Likes);
  const [creating, setProcessing] = useState(false);
  const [name, setName] = useState("");
  const [filters, setFilters] = useState<PlaylistFilter[]>([
    {
      kind: PlaylistFilterKind.Artist,
      op: PlaylistFilterOperator.Is,
      value: "",
    },
  ]);
  const [validated, setValidated] = useState(false);

  const navigate = useNavigate();

  const addFilter = () => {
    setFilters([
      ...filters,
      {
        kind: PlaylistFilterKind.Artist,
        op: PlaylistFilterOperator.Is,
        value: "",
      },
    ]);
  };

  const deleteFilter = (idx: number) => {
    setFilters([...filters.slice(0, idx), ...filters.slice(idx + 1)]);
  };

  const handleSubmit = async (event: any) => {
    event.preventDefault();
    event.stopPropagation();
    setValidated(true);
    const valid = event.currentTarget.checkValidity();

    if (valid) {
      setProcessing(true);
      const playlist: PlaylistRequest = {
        base: {
          kind: baseKind,
          platform: Platform.Spotify,
        },
        name,
        filters: filters.map(buildFilter),
      };
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

  const updateFilterKind = (idx: number, event: any) => {
    const filter = filters[idx];
    const kind = event.target.value;
    setFilters([
      ...filters.slice(0, idx),
      {
        ...filter,
        kind,
      },
      ...filters.slice(idx + 1),
    ]);
  };

  const updateFilterOperator = (idx: number, event: any) => {
    const filter = filters[idx];
    const op = event.target.value;
    setFilters([
      ...filters.slice(0, idx),
      {
        ...filter,
        op,
      },
      ...filters.slice(idx + 1),
    ]);
  };

  const updateFilterValue = (idx: number, event: any) => {
    const filter = filters[idx];
    const value = event.target.value;
    setFilters([
      ...filters.slice(0, idx),
      {
        ...filter,
        value,
      },
      ...filters.slice(idx + 1),
    ]);
  };

  const filterGroups = filters.map((filter, idx) => {
    let deleteBtn = <></>;
    if (idx > 0) {
      deleteBtn = (
        <Button variant="danger" onClick={() => deleteFilter(idx)}>
          <FontAwesomeIcon icon={faTrash} />
        </Button>
      );
    }
    return (
      <InputGroup key={idx.toString()} className="mb-3">
        <Form.Select
          value={filter.kind || PlaylistFilterKind.Artist}
          onChange={(event) => updateFilterKind(idx, event)}
        >
          <option value={PlaylistFilterKind.Artist}>Artist</option>
        </Form.Select>
        <Form.Select
          value={filter.op || PlaylistFilterOperator.Is}
          onChange={(event) => updateFilterOperator(idx, event)}
        >
          <option value={PlaylistFilterOperator.Is}>is</option>
        </Form.Select>
        <Form.Control
          required
          value={filter.value || ""}
          onChange={(event) => updateFilterValue(idx, event)}
        ></Form.Control>
        {deleteBtn}
      </InputGroup>
    );
  });

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
                value={name || ""}
                onChange={(event) => setName(event.target.value)}
              />
            </Form.Group>
            <Form.Group>
              <Form.Label>Base</Form.Label>
              <Form.Select
                defaultValue={baseKind}
                onChange={(event) =>
                  setBaseKind(event.target.value as BaseKind)
                }
              >
                <option value={BaseKind.Likes}>Likes</option>
              </Form.Select>
            </Form.Group>
            <Form.Group>
              <Form.Label>Filters</Form.Label>
              {filterGroups}
            </Form.Group>
            <div className="d-flex">
              <div className="col-9">
                <Button variant="secondary" onClick={addFilter}>
                  <FontAwesomeIcon icon={faPlus} className="inline" />
                  Add filter
                </Button>
              </div>
              <div className="col-3 text-end">{submitBtn}</div>
            </div>
          </Form>
        </Row>
      </Container>
    </>
  );
}

function buildFilter(filter: PlaylistFilter): any {
  switch (filter.kind) {
    case PlaylistFilterKind.Artist:
      return {
        artist: buildFilterOperator(filter),
      };
  }
}

function buildFilterOperator(filter: PlaylistFilter): any {
  switch (filter.op) {
    case PlaylistFilterOperator.Is:
      return {
        is: filter.value,
      };
  }
}
