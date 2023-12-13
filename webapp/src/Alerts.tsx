import React, { useContext } from "react";
import { AppContext } from ".";
import { Alert, Col, Container, Row } from "react-bootstrap";
import { t } from "i18next";

function Alerts(): JSX.Element {
  const state = useContext(AppContext);

  let errAlert = <></>;
  if (state.err !== null) {
    errAlert = (
      <Alert
        variant="danger"
        onClose={() => {
          state.setError(null);
        }}
        dismissible
      >
        {t(`error.${state.err}`)}
      </Alert>
    );
  }
  let infoAlert = <></>;
  if (state.info !== null) {
    infoAlert = (
      <Alert
        variant="success"
        onClose={() => {
          state.setInfo(null);
        }}
        dismissible
      >
        {t(`info.${state.info}`)}
      </Alert>
    );
  }

  return (
    <Container className="text-center">
      <Row>
        <Col>{errAlert}</Col>
      </Row>
      <Row>
        <Col>{infoAlert}</Col>
      </Row>
    </Container>
  );
}

export default Alerts;
