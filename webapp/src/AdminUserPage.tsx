import React, { useContext, useEffect, useState } from "react";
import { Button, Col, Container, Row } from "react-bootstrap";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faEye, faSpinner, faTrash } from "@fortawesome/free-solid-svg-icons";
import {
  AppContext,
  type AppError,
  PATH_NOT_FOUND,
  AppInfo,
  PATH_USR,
  PATH_PLAYLIST,
  PATH_SRC,
  PATH_ADMIN,
} from ".";
import { useLocation, useNavigate, useParams } from "react-router-dom";
import { type User, userById, deleteUser } from "./api";
import { handleError, removeToken } from "./utils";
import Alerts from "./Alerts";
import Nav from "./Nav";
import UserForm from "./UserForm";
import { t } from "i18next";
import BackButton from "./BackButton";
import { LinkContainer } from "react-router-bootstrap";
import CredentialsSection from "./CredentialsSection";
import ConfirmationModal from "./ConfirmationModal";

function AdminUserPage(): JSX.Element {
  const params = useParams();

  const state = useContext(AppContext);

  const navigate = useNavigate();
  const loc = useLocation();

  const [loading, setLoading] = useState(true);
  const [usr, setUsr] = useState<User | null>(null);
  const [showModal, setShowModal] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const remove = (): void => {
    if (params.id !== undefined) {
      setDeleting(true);
      void deleteUser(params.id)
        .then(() => {
          setShowModal(false);
          if (params.id === state.auth?.id) {
            removeToken(state);
            navigate("/");
          } else {
            state.setInfo(AppInfo.UserDeleted);
            navigate(-1);
          }
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
      void userById(params.id)
        .then((user) => {
          setUsr(user);
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
  if (usr == null || loading) {
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
          <Row className="mb-3">
            <Col xs={10} className="align-self-center">
              <h1 className="m-auto">{usr.id}</h1>
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
          <Row>
            <Col>
              <LinkContainer
                to={`${PATH_ADMIN}${PATH_USR}/${usr.id}${PATH_PLAYLIST}`}
                state={{
                  history: [...(loc.state?.history ?? []), loc.pathname],
                }}
              >
                <Button variant="primary" as="a" className="me-3">
                  <FontAwesomeIcon icon={faEye} className="inline-icon" />
                  {t("title.playlists")}
                </Button>
              </LinkContainer>
              <LinkContainer
                to={`${PATH_ADMIN}${PATH_USR}/${usr.id}${PATH_SRC}`}
                state={{
                  history: [...(loc.state?.history ?? []), loc.pathname],
                }}
              >
                <Button variant="primary" as="a">
                  <FontAwesomeIcon icon={faEye} className="inline-icon" />
                  {t("title.sources")}
                </Button>
              </LinkContainer>
            </Col>
          </Row>
        </Container>
        <UserForm usr={usr} className="mb-4" />
        <CredentialsSection creds={usr.creds} />
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
          setShowModal(false);
        }}
        onConfirm={remove}
        text="paragraph.delete-user"
      />
      {div}
    </>
  );
}

export default AdminUserPage;
