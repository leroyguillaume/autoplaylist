import React, { useContext, useEffect, useState } from "react";
import { Button, Col, Container, Row } from "react-bootstrap";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faSpinner, faTrash } from "@fortawesome/free-solid-svg-icons";
import { useNavigate } from "react-router-dom";
import { type User, userById, deleteUser } from "./api";
import { handleError, removeToken } from "./utils";
import Alerts from "./Alerts";
import Nav from "./Nav";
import { t } from "i18next";
import BackButton from "./BackButton";
import CredentialsSection from "./CredentialsSection";
import { AppContext, type AppError } from ".";
import ConfirmationModal from "./ConfirmationModal";

function MyAccountPage(): JSX.Element {
  const state = useContext(AppContext);

  const navigate = useNavigate();

  const [loading, setLoading] = useState(true);
  const [usr, setUsr] = useState<User | null>(null);
  const [showModal, setShowModal] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const remove = (): void => {
    setDeleting(true);
    void deleteUser(state.auth?.id ?? "")
      .then(() => {
        setShowModal(false);
        removeToken(state);
        navigate("/");
      })
      .catch((err: AppError) => {
        handleError(err, state, navigate);
      })
      .finally(() => {
        setDeleting(false);
      });
  };

  useEffect(() => {
    setLoading(true);
    void userById(state.auth?.id ?? "")
      .then((user) => {
        setUsr(user);
      })
      .catch((err: AppError) => {
        handleError(err, state, navigate);
      })
      .finally(() => {
        setLoading(false);
      });
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
        <Container className="mb-4">
          <Row className="mb-3">
            <Col xs={10} className="align-self-center">
              <h1 className="m-auto">{t("title.my-account")}</h1>
            </Col>
          </Row>
          <Row>
            <Col className="align-self-center">
              <Button
                variant="danger"
                onClick={() => {
                  setShowModal(true);
                }}
              >
                <FontAwesomeIcon icon={faTrash} className="inline-icon" />
                {t("label.delete")}
              </Button>
            </Col>
          </Row>
        </Container>
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
        text="paragraph.delete-my-account"
      />
      {div}
    </>
  );
}

export default MyAccountPage;
