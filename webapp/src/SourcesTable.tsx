import React, { useContext, useEffect, useState } from "react";
import { Col, Container, Row, Table } from "react-bootstrap";
import { t } from "i18next";
import { AppContext, AppInfo, type AppError, LIMIT } from ".";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faSpinner } from "@fortawesome/free-solid-svg-icons";
import Pagination from "./Pagination";
import { handleError } from "./utils";
import { useNavigate } from "react-router";
import SourceTd from "./SourceTd";
import SynchronizationTd from "./SynchronizationTd";
import OwnerTd from "./OwnerTd";
import {
  type Page,
  type PageRequest,
  type Source,
  sources,
  startSourceSynchronization,
  userSources,
} from "./api";
import SynchronizeButton from "./SynchronizeButton";

type Scope = "all" | "authenticatedUser" | { user: string };

interface Props {
  page: number;
  scope: Scope;
  onPageChange: (page: number) => void;
}

function SourcesTable(props: Props): JSX.Element {
  const state = useContext(AppContext);

  const navigate = useNavigate();

  const [page, setPage] = useState<Page<Source> | null>(null);
  const [req, setReq] = useState<PageRequest>({
    limit: LIMIT,
    offset: LIMIT * (props.page - 1),
  });

  const [refreshing, setRefreshing] = useState<boolean>(true);

  const refresh = (): void => {
    setRefreshing(true);
    let promise;
    if (props.scope === "all") {
      promise = sources(req);
    } else if (props.scope === "authenticatedUser") {
      promise = userSources(state.auth?.id ?? "", req);
    } else {
      promise = userSources(props.scope.user, req);
    }
    promise
      .then((page) => {
        setPage(page);
        props.onPageChange(page.req.offset / page.req.limit + 1);
      })
      .catch((err: AppError) => {
        handleError(err, state, navigate);
      })
      .finally(() => {
        setRefreshing(false);
      });
  };

  const startSynchronization = (id: string): void => {
    void startSourceSynchronization(id)
      .catch((err: AppError) => {
        handleError(err, state, navigate);
      })
      .then(() => {
        state.setInfo(AppInfo.SourceSynchronizationStarted);
      });
  };

  useEffect(() => {
    const id = setTimeout(refresh, 500);
    return () => {
      clearTimeout(id);
    };
  }, [name, req]);

  let ownerTh = <></>;
  if (props.scope !== "authenticatedUser") {
    ownerTh = <th>{t("label.owner")}</th>;
  }

  const trs = page?.items.map((src: Source) => {
    let ownerTd = <></>;
    if (props.scope !== "authenticatedUser") {
      ownerTd = <OwnerTd src={src} />;
    }

    return (
      <tr key={src.id}>
        <SourceTd kind={src.kind} />
        {ownerTd}
        <SynchronizationTd sync={src.sync} />
        <td className="text-center">
          <SynchronizeButton
            sync={src.sync}
            onClick={() => {
              startSynchronization(src.id);
            }}
          />
        </td>
      </tr>
    );
  });
  let table = <></>;
  if (refreshing) {
    table = (
      <Row>
        <Col>
          <FontAwesomeIcon icon={faSpinner} spin />
        </Col>
      </Row>
    );
  } else if (page !== null) {
    table = (
      <>
        <Row className="mb-3 mb-sm-0">
          <Col>
            <Table striped bordered hover responsive>
              <thead className="text-center">
                <tr>
                  <th>{t("label.name")}</th>
                  <th>{t("label.source")}</th>
                  {ownerTh}
                  <th>{t("label.status")}</th>
                </tr>
              </thead>
              <tbody>{trs}</tbody>
            </Table>
          </Col>
        </Row>
        <Pagination
          req={req}
          total={page.total}
          onChange={(req) => {
            setRefreshing(true);
            setReq(req);
          }}
        />
      </>
    );
  }

  return <Container>{table}</Container>;
}

export default SourcesTable;
