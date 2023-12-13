import React, { useEffect, useState } from "react";
import Nav from "./Nav";
import { Col, Container, Row } from "react-bootstrap";
import { t } from "i18next";
import Alerts from "./Alerts";
import { PARAM_PAGE, PARAM_Q } from ".";
import { useLocation, useNavigate, useSearchParams } from "react-router-dom";
import TracksTable from "./TracksTable";

function AdminTracksPage(): JSX.Element {
  const navigate = useNavigate();
  const loc = useLocation();

  const [params] = useSearchParams();
  const [page, setPage] = useState(Number(params.get(PARAM_PAGE) ?? "1"));
  const [query, setQuery] = useState(params.get(PARAM_Q) ?? "");

  useEffect(() => {
    const params = new URLSearchParams();
    params.set(PARAM_PAGE, page.toString());
    params.set(PARAM_Q, query);
    navigate(`${loc.pathname}?${params.toString()}`, {
      replace: true,
      state: loc.state,
    });
  }, [page, query]);

  return (
    <>
      <Nav />
      <Alerts />
      <Container className="mb-3">
        <Row>
          <Col>
            <h1>{t("title.tracks")}</h1>
          </Col>
        </Row>
      </Container>
      <TracksTable
        page={page}
        onPageChange={setPage}
        name={query}
        onQueryChange={(query) => {
          setQuery(query);
          setPage(1);
        }}
      />
    </>
  );
}

export default AdminTracksPage;
