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
  type Track,
  tracks,
  deleteTrack,
  Platform,
} from "./api";
import {
  AppContext,
  AppInfo,
  type AppError,
  LIMIT,
  PATH_ADMIN,
  PATH_TRACK,
} from ".";
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
import ConfirmationModal from "./ConfirmationModal";

interface Props {
  name: string;
  page: number;
  onQueryChange: (name: string) => void;
  onPageChange: (page: number) => void;
}

function TracksTable(props: Props): JSX.Element {
  const state = useContext(AppContext);

  const navigate = useNavigate();
  const loc = useLocation();

  const [page, setPage] = useState<Page<Track> | null>(null);
  const [req, setReq] = useState<PageRequest>({
    limit: LIMIT,
    offset: LIMIT * (props.page - 1),
  });
  const [query, setQuery] = useState(props.name);

  const [refreshing, setRefreshing] = useState<boolean>(true);
  const [id, setId] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<boolean>(false);

  const refresh = (): void => {
    setRefreshing(true);
    tracks(req, query)
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
      void deleteTrack(id)
        .catch((err: AppError) => {
          handleError(err, state, navigate);
        })
        .then(() => {
          setId(null);
          state.setInfo(AppInfo.TrackDeleted);
          refresh();
        })
        .finally(() => {
          setDeleting(false);
        });
    }
  };

  useEffect(() => {
    const id = setTimeout(refresh, 500);
    return () => {
      clearTimeout(id);
    };
  }, [query, req]);

  const trs = page?.items.map((track: Track) => {
    let titleA;
    let platform;
    if (track.platform === Platform.Spotify) {
      titleA = (
        <td>
          <a href={`https://open.spotify.com/track/${track.platformId}`}>
            {track.title}
          </a>
        </td>
      );
      platform = "Spotify";
    }
    return (
      <tr key={track.id}>
        <td>{titleA}</td>
        <td>{track.artists.join(", ")}</td>
        <td>{track.album.name}</td>
        <td>{track.year}</td>
        <td>{platform}</td>
        <td className="text-center">
          <LinkContainer
            to={`${PATH_ADMIN}${PATH_TRACK}/${track.id}`}
            state={{ history: [...(loc.state?.history ?? []), loc.pathname] }}
          >
            <Button as="a" variant="primary" className="me-1 mb-1 mb-lg-0">
              <FontAwesomeIcon icon={faPencil} />
            </Button>
          </LinkContainer>
          <Button
            variant="danger"
            onClick={() => {
              setId(track.id);
            }}
            className="mb-1 mb-lg-0"
          >
            <FontAwesomeIcon icon={faTrash} />
          </Button>
        </td>
      </tr>
    );
  });

  let table;
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
              defaultValue={query}
              type="text"
              placeholder={t("placeholder.search")}
              onChange={(evt) => {
                setQuery(evt.target.value);
                props.onQueryChange(evt.target.value);
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
                  <th>{t("label.title")}</th>
                  <th>{t("label.artists")}</th>
                  <th>{t("label.album")}</th>
                  <th>{t("label.year")}</th>
                  <th>{t("label.platform")}</th>
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
        text="paragraph.delete-track"
      />
      <Container>{table}</Container>
    </>
  );
}

export default TracksTable;
