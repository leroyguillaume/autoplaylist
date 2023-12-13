import React from "react";
import { Col, Container, Row, Table } from "react-bootstrap";
import { type Credentials } from "./api";
import { t } from "i18next";

interface Props {
  creds: Credentials;
}

function CredentialsSection(props: Props): JSX.Element {
  const trs: JSX.Element[] = [];
  const spotifyCreds = props.creds.spotify;
  if (spotifyCreds !== undefined) {
    trs.push(
      <tr key="spotify">
        <td>
          <a href={`https://open.spotify.com/user/${spotifyCreds.id}`}>
            Spotify
          </a>
        </td>
        <td>{spotifyCreds.id}</td>
        <td>{spotifyCreds.email}</td>
      </tr>,
    );
  }

  return (
    <Container>
      <Row className="mb-3">
        <Col>
          <h2>{t("title.credentials")}</h2>
        </Col>
      </Row>
      <Row>
        <Col>
          <Table striped bordered hover>
            <thead className="text-center">
              <tr>
                <th>{t("label.platform")}</th>
                <th>{t("label.platform-id")}</th>
                <th>{t("label.email")}</th>
              </tr>
            </thead>
            <tbody>{trs}</tbody>
          </Table>
        </Col>
      </Row>
    </Container>
  );
}

export default CredentialsSection;
