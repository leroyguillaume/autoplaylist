import React, { useEffect, useState } from "react";
import Nav from "./Nav";
import { Col, Container, Row } from "react-bootstrap";
import { t } from "i18next";
import PlaylistsTable from "./PlaylistsTable";
import Alerts from "./Alerts";
import { PARAM_PAGE, PARAM_Q, PATH_NOT_FOUND } from ".";
import {
  useLocation,
  useNavigate,
  useParams,
  useSearchParams,
} from "react-router-dom";
import BackButton from "./BackButton";

function AdminUserPlaylistsPage(): JSX.Element {
  const params = useParams();

  const navigate = useNavigate();
  const loc = useLocation();

  const [searchParams] = useSearchParams();
  const [page, setPage] = useState(Number(searchParams.get(PARAM_PAGE) ?? "1"));
  const [name, setName] = useState(searchParams.get(PARAM_Q) ?? "");

  const updateName = (name: string): void => {
    setName(name);
    setPage(1);
  };

  useEffect(() => {
    if (params.id === undefined) {
      navigate(PATH_NOT_FOUND);
    }
  }, []);

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
      <BackButton />
      <Container className="mb-3">
        <Row>
          <Col>
            <h1>{t("title.playlists")}</h1>
          </Col>
        </Row>
      </Container>
      <PlaylistsTable
        scope={{ user: params.id ?? "" }}
        page={page}
        onPageChange={setPage}
        name={name}
        onNameChange={updateName}
      />
    </>
  );
}

export default AdminUserPlaylistsPage;
