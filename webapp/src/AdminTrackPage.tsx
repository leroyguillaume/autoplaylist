import React, { useContext, useEffect, useState } from "react";
import { Button, Col, Container, Row } from "react-bootstrap";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faSpinner, faTrash } from "@fortawesome/free-solid-svg-icons";
import { AppContext, type AppError, PATH_NOT_FOUND, AppInfo } from ".";
import { useNavigate, useParams } from "react-router-dom";
import { deletePlaylist, trackById, type Track } from "./api";
import { handleError } from "./utils";
import Alerts from "./Alerts";
import Nav from "./Nav";
import { t } from "i18next";
import BackButton from "./BackButton";
import ConfirmationModal from "./ConfirmationModal";
import TrackForm from "./TrackForm";

function AdminTrackPage(): JSX.Element {
  const params = useParams();

  const state = useContext(AppContext);

  const navigate = useNavigate();

  const [loading, setLoading] = useState(true);
  const [track, setTrack] = useState<Track | null>(null);
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
      void trackById(params.id)
        .then((track) => {
          setTrack(track);
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
  if (track == null || loading) {
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
              <h1 className="m-auto">{track.id}</h1>
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
        <TrackForm track={track} />
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

export default AdminTrackPage;
