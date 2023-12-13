import React from "react";
import { Button, Col, Container, Row } from "react-bootstrap";
import { t } from "i18next";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faArrowLeft } from "@fortawesome/free-solid-svg-icons";
import { useLocation } from "react-router";
import { LinkContainer } from "react-router-bootstrap";
import { backPath } from "./utils";

function BackButton(): JSX.Element {
  const loc = useLocation();

  return (
    <>
      <Container>
        <Row className="mb-3">
          <Col>
            <LinkContainer
              to={backPath(loc)}
              state={{
                history:
                  loc.state?.history?.slice(
                    0,
                    loc.state?.history?.length - 1,
                  ) ?? [],
              }}
            >
              <Button variant="secondary" as="a">
                <FontAwesomeIcon icon={faArrowLeft} className="inline-icon" />
                {t("label.back")}
              </Button>
            </LinkContainer>
          </Col>
        </Row>
      </Container>
    </>
  );
}

export default BackButton;
