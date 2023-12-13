import React, { useEffect, useState } from "react";
import Nav from "./Nav";
import { Col, Container, Row } from "react-bootstrap";
import { t } from "i18next";
import Alerts from "./Alerts";
import { PARAM_PAGE, PARAM_Q } from ".";
import { useLocation, useNavigate, useSearchParams } from "react-router-dom";
import UsersTable from "./UsersTable";

function AdminPlaylistsPage(): JSX.Element {
  const navigate = useNavigate();
  const loc = useLocation();

  const [params] = useSearchParams();
  const [page, setPage] = useState(Number(params.get(PARAM_PAGE) ?? "1"));
  const [email, setEmail] = useState(params.get(PARAM_Q) ?? "");

  const updateEmail = (name: string): void => {
    setEmail(name);
    setPage(1);
  };

  useEffect(() => {
    const params = new URLSearchParams();
    params.set(PARAM_PAGE, page.toString());
    params.set(PARAM_Q, email);
    navigate(`${loc.pathname}?${params.toString()}`, {
      replace: true,
      state: loc.state,
    });
  }, [page, email]);

  return (
    <>
      <Nav />
      <Alerts />
      <Container className="mb-3">
        <Row>
          <Col>
            <h1>{t("title.users")}</h1>
          </Col>
        </Row>
      </Container>
      <UsersTable
        page={page}
        onPageChange={setPage}
        name={email}
        onEmailChange={updateEmail}
      />
    </>
  );
}

export default AdminPlaylistsPage;
