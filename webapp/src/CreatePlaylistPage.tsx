import React from "react";
import Nav from "./Nav";
import { Col, Container, Row } from "react-bootstrap";
import { t } from "i18next";
import Alerts from "./Alerts";
import PlaylistForm from "./PlaylistForm";
import BackButton from "./BackButton";

function CreatePlaylistPage(): JSX.Element {
  return (
    <>
      <Nav />
      <Alerts />
      <BackButton />
      <Container>
        <Row>
          <Col>
            <h1>{t("title.create-playlist")}</h1>
          </Col>
        </Row>
      </Container>
      <PlaylistForm />
    </>
  );
}

export default CreatePlaylistPage;
