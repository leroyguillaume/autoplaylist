import React, { useEffect, useState } from "react";
import Nav from "./Nav";
import { Col, Container, Row } from "react-bootstrap";
import { t } from "i18next";
import Alerts from "./Alerts";
import { PARAM_PAGE } from ".";
import { useLocation, useNavigate, useSearchParams } from "react-router-dom";
import SourcesTable from "./SourcesTable";

function AdminSourcesPage(): JSX.Element {
  const navigate = useNavigate();
  const loc = useLocation();

  const [params] = useSearchParams();
  const [page, setPage] = useState(Number(params.get(PARAM_PAGE) ?? "1"));

  useEffect(() => {
    const params = new URLSearchParams();
    params.set(PARAM_PAGE, page.toString());
    navigate(`${loc.pathname}?${params.toString()}`, {
      replace: true,
      state: loc.state,
    });
  }, [page]);

  return (
    <>
      <Nav />
      <Alerts />
      <Container className="mb-3">
        <Row>
          <Col>
            <h1>{t("title.sources")}</h1>
          </Col>
        </Row>
      </Container>
      <SourcesTable scope="all" page={page} onPageChange={setPage} />
    </>
  );
}

export default AdminSourcesPage;
