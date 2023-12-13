import React, { useEffect, useState } from "react";
import Nav from "./Nav";
import { Col, Container, Row } from "react-bootstrap";
import { t } from "i18next";
import Alerts from "./Alerts";
import { PARAM_PAGE, PATH_NOT_FOUND } from ".";
import {
  useLocation,
  useNavigate,
  useParams,
  useSearchParams,
} from "react-router-dom";
import SourcesTable from "./SourcesTable";
import BackButton from "./BackButton";

function AdminUserSourcesPage(): JSX.Element {
  const params = useParams();

  const navigate = useNavigate();
  const loc = useLocation();

  const [searchParams] = useSearchParams();
  const [page, setPage] = useState(Number(searchParams.get(PARAM_PAGE) ?? "1"));

  useEffect(() => {
    if (params.id === undefined) {
      navigate(PATH_NOT_FOUND);
    }
  }, []);

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
      <BackButton />
      <Container className="mb-3">
        <Row>
          <Col>
            <h1>{t("title.sources")}</h1>
          </Col>
        </Row>
      </Container>
      <SourcesTable
        scope={{ user: params.id ?? "" }}
        page={page}
        onPageChange={setPage}
      />
    </>
  );
}

export default AdminUserSourcesPage;
