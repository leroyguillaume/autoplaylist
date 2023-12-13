import React, { useEffect, useState } from "react";
import Nav from "./Nav";
import { Col, Container, Row } from "react-bootstrap";
import { t } from "i18next";
import PlaylistsTable from "./PlaylistsTable";
import Alerts from "./Alerts";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faPlus } from "@fortawesome/free-solid-svg-icons";
import { PARAM_PAGE, PARAM_Q, PATH_NEW, PATH_PLAYLIST } from ".";
import { useLocation, useNavigate, useSearchParams } from "react-router-dom";
import { LinkContainer } from "react-router-bootstrap";

function MyPlaylistsPage(): JSX.Element {
  const navigate = useNavigate();
  const loc = useLocation();

  const [params] = useSearchParams();
  const [page, setPage] = useState(Number(params.get(PARAM_PAGE) ?? "1"));
  const [name, setName] = useState(params.get(PARAM_Q) ?? "");

  const updateName = (name: string): void => {
    setName(name);
    setPage(1);
  };

  useEffect(() => {
    const params = new URLSearchParams();
    params.set(PARAM_PAGE, page.toString());
    params.set(PARAM_Q, name);
    navigate(`${loc.pathname}?${params.toString()}`, {
      replace: true,
      state: loc.state,
    });
  }, [page, name]);

  return (
    <>
      <Nav />
      <Alerts />
      <Container className="mb-3">
        <Row>
          <Col>
            <h1 className="m-auto">{t("title.my-playlists")}</h1>
          </Col>
          <Col className="align-self-center">
            <LinkContainer
              to={`${PATH_PLAYLIST}${PATH_NEW}`}
              state={{ history: [...(loc.state?.history ?? []), loc.pathname] }}
            >
              <a className="btn btn-success float-end">
                <FontAwesomeIcon icon={faPlus} className="inline-icon" />
                {t("label.create-playlist")}
              </a>
            </LinkContainer>
          </Col>
        </Row>
      </Container>
      <PlaylistsTable
        scope="authenticatedUser"
        page={page}
        onPageChange={setPage}
        name={name}
        onNameChange={updateName}
      />
    </>
  );
}

export default MyPlaylistsPage;
