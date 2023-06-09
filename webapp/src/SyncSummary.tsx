import { useContext, useEffect, useState } from "react";
import { Container, Row } from "react-bootstrap";
import { useNavigate, useSearchParams } from "react-router-dom";
import BaseTable from "./BaseTable";
import Header from "./Header";
import { doGet, doPut, handleCommonErrors } from "./api";
import { Context, pageNumberFromPlaylist } from "./ctx";
import { Base, Page } from "./domain";

const BASE_PAGE_SIZE = 5;

export default function SyncSummary() {
  const ctx = useContext(Context);

  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();

  const initialBasePageNb = pageNumberFromPlaylist("basePage", params);
  const [basePage, setBasePage] = useState<Page<Base> | null>(null);
  const [basePageNb, setBasePageNb] = useState(initialBasePageNb);
  const [fetchingBasePage, setFetchingBasePage] = useState(false);

  const fetchBasePage = async (nb: number) => {
    setFetchingBasePage(true);
    await doGet<Page<Base>>(
      "sync/base",
      {
        limit: BASE_PAGE_SIZE,
        offset: (nb - 1) * BASE_PAGE_SIZE,
      },
      ctx
    )
      .then((page) => {
        const maxNb = Math.max(1, Math.ceil(page.total / BASE_PAGE_SIZE));
        if (nb > maxNb) {
          return fetchBasePage(maxNb);
        } else {
          setBasePage(page);
          setBasePageNb(nb);
          setParams({
            basePage: nb.toString(),
          });
        }
      })
      .catch((err) => {
        handleCommonErrors(err, ctx, navigate);
      })
      .finally(() => {
        setFetchingBasePage(false);
      });
  };

  const syncBase = async (id: string) => {
    setFetchingBasePage(true);
    await doPut(`sync/base/${id}`, null, ctx)
      .then(() => fetchBasePage(basePageNb))
      .catch((err) => {
        handleCommonErrors(err, ctx, navigate);
      })
      .finally(() => {
        setFetchingBasePage(false);
      });
  };

  useEffect(() => {
    (async function () {
      await fetchBasePage(basePageNb);
    })();
  }, []);

  return (
    <>
      <Header />
      <Container>
        <Row>
          <div className="d-flex">
            <h3>Sync summary</h3>
          </div>
        </Row>
        <Row>
          <div className="d-flex">
            <h4>Bases</h4>
          </div>
          <Row>
            <BaseTable
              fetching={fetchingBasePage}
              page={basePage}
              pageChanged={fetchBasePage}
              pageNb={basePageNb}
              pageSize={BASE_PAGE_SIZE}
              handleSync={syncBase}
            />
          </Row>
        </Row>
      </Container>
    </>
  );
}
