import React, { useContext, useEffect, useState } from "react";
import {
  Button,
  Col,
  Container,
  FormControl,
  Row,
  Table,
} from "react-bootstrap";
import { t } from "i18next";
import {
  type Page,
  type PageRequest,
  type Playlist,
  deletePlaylist,
  startPlaylistSynchronization,
  playlists,
  userPlaylists,
} from "./api";
import { AppContext, AppInfo, type AppError, LIMIT, PATH_PLAYLIST } from ".";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import {
  faPencil,
  faSpinner,
  faTrash,
} from "@fortawesome/free-solid-svg-icons";
import Pagination from "./Pagination";
import { handleError } from "./utils";
import { useLocation, useNavigate } from "react-router";
import { LinkContainer } from "react-router-bootstrap";
import SourceTd from "./SourceTd";
import SynchronizationTd from "./SynchronizationTd";
import OwnerTd from "./OwnerTd";
import SynchronizeButton from "./SynchronizeButton";
import ConfirmationModal from "./ConfirmationModal";

type Scope = "all" | "authenticatedUser" | { user: string };

interface Props {
  name: string;
  page: number;
  scope: Scope;
  onNameChange: (name: string) => void;
  onPageChange: (page: number) => void;
}

function PlaylistsTable(props: Props): JSX.Element {
  const state = useContext(AppContext);

  const navigate = useNavigate();
  const loc = useLocation();

  const [page, setPage] = useState<Page<Playlist> | null>(null);
  const [req, setReq] = useState<PageRequest>({
    limit: LIMIT,
    offset: LIMIT * (props.page - 1),
  });
  const [name, setName] = useState(props.name);

  const [id, setId] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState<boolean>(true);
  const [deleting, setDeleting] = useState<boolean>(false);

  const refresh = (): void => {
    setRefreshing(true);
    let promise;
    if (props.scope === "all") {
      promise = playlists(req, name);
    } else if (props.scope === "authenticatedUser") {
      promise = userPlaylists(state.auth?.id ?? "", req, name);
    } else {
      promise = userPlaylists(props.scope.user, req, name);
    }
    promise
      .then((page) => {
        setPage(page);
        props.onPageChange(page.req.offset / page.req.limit + 1);
      })
      .catch((err: AppError) => {
        handleError(err, state, navigate);
      })
      .finally(() => {
        setRefreshing(false);
      });
  };

  const remove = (): void => {
    if (id !== null) {
      setDeleting(true);
      void deletePlaylist(id)
        .catch((err: AppError) => {
          handleError(err, state, navigate);
        })
        .then(() => {
          setId(null);
          state.setInfo(AppInfo.PlaylistDeleted);
          refresh();
        })
        .finally(() => {
          setDeleting(false);
        });
    }
  };

  const startSynchronization = (id: string): void => {
    void startPlaylistSynchronization(id)
      .catch((err: AppError) => {
        handleError(err, state, navigate);
      })
      .then(() => {
        state.setInfo(AppInfo.PlaylistSynchronizationStarted);
      });
  };

  const updateName = (name: string): void => {
    setName(name);
    props.onNameChange(name);
  };

  useEffect(() => {
    const id = setTimeout(refresh, 500);
    return () => {
      clearTimeout(id);
    };
  }, [name, req]);

  let ownerTh = <></>;
  if (props.scope !== "authenticatedUser") {
    ownerTh = <th>{t("label.owner")}</th>;
  }

  const trs = page?.items.map((playlist: Playlist) => {
    let ownerTd = <></>;
    if (props.scope !== "authenticatedUser") {
      ownerTd = <OwnerTd src={playlist.src} />;
    }

    return (
      <tr key={playlist.id}>
        <td>{playlist.name}</td>
        <SourceTd kind={playlist.src.kind} />
        {ownerTd}
        <SynchronizationTd sync={playlist.sync} />
        <td className="text-center">
          <LinkContainer
            to={`${PATH_PLAYLIST}/${playlist.id}`}
            state={{ history: [...(loc.state?.history ?? []), loc.pathname] }}
          >
            <Button as="a" variant="primary" className="me-1 mb-1 mb-lg-0">
              <FontAwesomeIcon icon={faPencil} />
            </Button>
          </LinkContainer>
          <SynchronizeButton
            sync={playlist.sync}
            onClick={() => {
              startSynchronization(playlist.id);
            }}
          />
          <Button
            variant="danger"
            onClick={() => {
              setId(playlist.id);
            }}
            className="mb-1 mb-lg-0"
          >
            <FontAwesomeIcon icon={faTrash} />
          </Button>
        </td>
      </tr>
    );
  });
  let table = <></>;
  if (refreshing) {
    table = (
      <Row>
        <Col>
          <FontAwesomeIcon icon={faSpinner} spin />
        </Col>
      </Row>
    );
  } else if (page !== null) {
    table = (
      <>
        <Row className="mb-3">
          <Col xs={12} lg={{ span: 6, offset: 6 }} xl={{ span: 4, offset: 8 }}>
            <FormControl
              defaultValue={name}
              type="text"
              placeholder={t("placeholder.search")}
              onChange={(evt) => {
                updateName(evt.target.value);
              }}
              autoFocus
            />
          </Col>
        </Row>
        <Row className="mb-3 mb-sm-0">
          <Col>
            <Table striped bordered hover responsive>
              <thead className="text-center">
                <tr>
                  <th>{t("label.name")}</th>
                  <th>{t("label.source")}</th>
                  {ownerTh}
                  <th>{t("label.status")}</th>
                  <th>{t("label.actions")}</th>
                </tr>
              </thead>
              <tbody>{trs}</tbody>
            </Table>
          </Col>
        </Row>
        <Pagination
          req={req}
          total={page.total}
          onChange={(req) => {
            setRefreshing(true);
            setReq(req);
          }}
        />
      </>
    );
  }

  return (
    <>
      <ConfirmationModal
        deleting={deleting}
        show={id !== null}
        onCancel={() => {
          setId(null);
        }}
        onConfirm={remove}
        text="paragraph.delete-playlist"
      />
      <Container>{table}</Container>
    </>
  );
}

export default PlaylistsTable;
