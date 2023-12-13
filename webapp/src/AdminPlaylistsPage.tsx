import React, { useEffect, useState } from "react";
import Nav from "./Nav";
import { Col, Container, Row } from "react-bootstrap";
import { t } from "i18next";
import PlaylistsTable from "./PlaylistsTable";
import Alerts from "./Alerts";
import { PARAM_PAGE, PARAM_Q } from ".";
import { useLocation, useNavigate, useSearchParams } from "react-router-dom";

function AdminPlaylistsPage(): JSX.Element {
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
            <h1>{t("title.playlists")}</h1>
          </Col>
        </Row>
      </Container>
      <PlaylistsTable
        scope="all"
        page={page}
        onPageChange={setPage}
        name={name}
        onNameChange={updateName}
      />
    </>
  );
}

export default AdminPlaylistsPage;
