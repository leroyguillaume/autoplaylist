import { faPlus, faSpinner, faTrash } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { useContext, useEffect, useState } from "react";
import { Button, Container, Pagination, Row, Table } from "react-bootstrap";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import Header from "./Header";
import { HttpError, get } from "./api";
import { Context, Error } from "./ctx";
import { Page, Query } from "./domain";

const LIMIT = 10;

export default function Home() {
  const ctx = useContext(Context);

  const [fetching, setFetching] = useState(false);
  const [page, setPage] = useState<Page<Query> | null>(null);
  const [pageNb, setPageNb] = useState<number>(1);

  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();

  const fetchPage = async (nb: number) => {
    setFetching(true);
    await get<Page<Query>>("query", {
      limit: LIMIT,
      offset: (nb - 1) * LIMIT,
    })
      .then((page) => {
        setPage(page);
        setPageNb(nb);
        setParams({
          page: nb.toString(),
        });
      })
      .catch((err) => {
        if (err === HttpError.Unauthorized) {
          ctx.setError(Error.Unauthorized);
          navigate("/");
        } else {
          ctx.setError(Error.Unexpected);
        }
      })
      .finally(() => {
        setFetching(false);
      });
  };

  useEffect(() => {
    (async function () {
      let pageParam = params.get("page");
      if (pageParam == null) {
        pageParam = "1";
      }
      let page;
      try {
        page = parseInt(pageParam);
      } catch (exception: any) {
        page = 1;
      }
      await fetchPage(page);
    })();
  }, []);

  let table = <></>;
  if (page === null || fetching) {
    table = (
      <>
        <div className="text-center">
          <FontAwesomeIcon icon={faSpinner} spin size="2x" />
        </div>
      </>
    );
  } else {
    const trs = page.content.map((query) => {
      const creationDate = new Date(query.creationDate);
      return (
        <tr key={query.id}>
          <td>{creationDate.toLocaleString()}</td>
          <td>{query.base.kind}</td>
          <td>
            <Button className="btn-sm" variant="danger">
              <FontAwesomeIcon icon={faTrash} className="inline" />
              Delete
            </Button>
          </td>
        </tr>
      );
    });
    const maxPageNb = Math.ceil(page.total / LIMIT);
    let paginationFirst;
    let paginationPrev;
    let paginationNext;
    let paginationLast;
    if (pageNb <= 1) {
      paginationFirst = <></>;
      paginationPrev = <></>;
    } else {
      paginationFirst = <Pagination.First onClick={() => fetchPage(1)} />;
      paginationPrev = (
        <Pagination.Prev onClick={() => fetchPage(pageNb - 1)} />
      );
    }
    if (pageNb >= maxPageNb) {
      paginationNext = <></>;
      paginationLast = <></>;
    } else {
      paginationNext = (
        <Pagination.Next onClick={() => fetchPage(pageNb + 1)} />
      );
      paginationLast = <Pagination.Last onClick={() => fetchPage(maxPageNb)} />;
    }
    table = (
      <>
        <div className="text-center">
          <Table bordered>
            <thead>
              <tr>
                <th>Creation date</th>
                <th>Base</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>{trs}</tbody>
          </Table>
        </div>
        <Pagination className="justify-content-end">
          {paginationFirst}
          {paginationPrev}
          {paginationNext}
          {paginationLast}
        </Pagination>
      </>
    );
  }

  return (
    <>
      <Header />
      <Container>
        <Row>
          <div className="d-flex title">
            <h3 className="col-8">My queries</h3>
            <div className="col-4 text-end">
              <Link className="btn btn-primary" to="/query">
                <FontAwesomeIcon className="inline" icon={faPlus} />
                Add query
              </Link>
            </div>
          </div>
        </Row>
        <Row>{table}</Row>
      </Container>
    </>
  );
}
