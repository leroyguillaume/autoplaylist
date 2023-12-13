import React, { useContext } from "react";
import Alerts from "./Alerts";
import Nav from "./Nav";
import { t } from "i18next";
import { Col, Container, Row } from "react-bootstrap";
import { AppContext } from ".";

function NotFoundPage(): JSX.Element {
  const state = useContext(AppContext);

  let nav = <></>;
  if (state.auth !== null) {
    nav = <Nav />;
  }

  return (
    <>
      {nav}
      <Alerts />
      <Container>
        <Row>
          <Col>
            <h1>{t("title.not-found")}</h1>
          </Col>
        </Row>
      </Container>
    </>
  );
}

export default NotFoundPage;
