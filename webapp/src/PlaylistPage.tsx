import React, { useContext, useEffect, useState } from "react";
import { Button, Col, Container, Row } from "react-bootstrap";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faSpinner, faTrash } from "@fortawesome/free-solid-svg-icons";
import { AppContext, type AppError, PATH_NOT_FOUND, AppInfo } from ".";
import { useNavigate, useParams } from "react-router-dom";
import { deletePlaylist, type Playlist, playlistById } from "./api";
import { handleError } from "./utils";
import Alerts from "./Alerts";
import Nav from "./Nav";
import { t } from "i18next";
import PlaylistForm from "./PlaylistForm";
import BackButton from "./BackButton";
import ConfirmationModal from "./ConfirmationModal";

function PlaylistPage(): JSX.Element {
  const params = useParams();

  const state = useContext(AppContext);

  const navigate = useNavigate();

  const [loading, setLoading] = useState(true);
  const [playlist, setPlaylist] = useState<Playlist | null>(null);
  const [showModal, setShowModal] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const remove = (): void => {
    if (params.id !== undefined) {
      setDeleting(true);
      void deletePlaylist(params.id)
        .then(() => {
          setShowModal(false);
          state.setInfo(AppInfo.PlaylistDeleted);
          navigate(-1);
        })
        .catch((err: AppError) => {
          handleError(err, state, navigate);
        })
        .finally(() => {
          setDeleting(false);
        });
    }
  };

  useEffect(() => {
    setLoading(true);
    if (params.id === undefined) {
      navigate(PATH_NOT_FOUND);
    } else {
      void playlistById(params.id)
        .then((playlist) => {
          setPlaylist(playlist);
        })
        .catch((err: AppError) => {
          handleError(err, state, navigate);
        })
        .finally(() => {
          setLoading(false);
        });
    }
  }, []);

  let div;
  if (playlist == null || loading) {
    div = (
      <Container>
        <Row>
          <Col>
            <FontAwesomeIcon icon={faSpinner} spin={true} />
          </Col>
        </Row>
      </Container>
    );
  } else {
    div = (
      <>
        <Container className="mb-3">
          <Row>
            <Col xs={10} className="align-self-center">
              <h1 className="m-auto">{playlist.name}</h1>
            </Col>
            <Col className="align-self-center">
              <Button
                variant="danger"
                onClick={() => {
                  setShowModal(true);
                }}
                className="float-md-end"
              >
                <FontAwesomeIcon icon={faTrash} className="inline-icon" />
                {t("label.delete")}
              </Button>
            </Col>
          </Row>
        </Container>
        <PlaylistForm playlist={playlist} />
      </>
    );
  }

  return (
    <>
      <Nav />
      <Alerts />
      <BackButton />
      <ConfirmationModal
        deleting={deleting}
        show={showModal}
        onCancel={() => {
          setDeleting(false);
        }}
        onConfirm={remove}
        text="paragraph.delete-playlist"
      />
      {div}
    </>
  );
}

export default PlaylistPage;
