import { faPlus, faSpinner, faTrash } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { useContext, useEffect, useState } from "react";
import { Button, Container, Row } from "react-bootstrap";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import Header from "./Header";
import Table from "./Table";
import { HttpError, doDelete, doGet } from "./api";
import { Context, Error, Info } from "./ctx";
import { Page, Query } from "./domain";

const LIMIT = 10;

export default function Home() {
  const ctx = useContext(Context);

  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();

  const initialQueryPageNb = pageNumberFromQuery("queryPage", params);

  const [queriesInDeletion, setQueriesInDeletion] = useState<string[]>([]);
  const [queryPage, setQueryPage] = useState<Page<Query> | null>(null);
  const [queryPageFetching, setQueryPageFetching] = useState(false);
  const [queryPageNb, setQueryPageNb] = useState(initialQueryPageNb);

  const queryTableThead = (
    <thead>
      <tr>
        <th>Creation date</th>
        <th>Base</th>
        <th>Action</th>
      </tr>
    </thead>
  );

  const deleteQuery = async (id: string) => {
    setQueriesInDeletion([...queriesInDeletion, id]);
    await doDelete(`query/${id}`, ctx)
      .then(() => {
        ctx.setInfo(Info.QueryDeleted);
        return fetchQueryPage(queryPageNb);
      })
      .finally(() => {
        const idx = queriesInDeletion.indexOf(id);
        if (idx > -1) {
          setQueriesInDeletion([
            ...queriesInDeletion.slice(0, idx),
            ...queriesInDeletion.slice(idx + 1),
          ]);
        }
      });
  };

  const buildQueryTrs = (page: Page<Query>) => {
    return page.content.map((query) => {
      const creationDate = new Date(query.creationDate);
      let deleteBtn;
      if (queriesInDeletion.indexOf(query.id) === -1) {
        deleteBtn = (
          <Button
            className="btn-sm"
            variant="danger"
            onClick={() => deleteQuery(query.id)}
          >
            <FontAwesomeIcon icon={faTrash} className="inline" />
            Delete
          </Button>
        );
      } else {
        deleteBtn = (
          <Button className="btn-sm" variant="danger" disabled={true}>
            <FontAwesomeIcon icon={faSpinner} spin className="inline" />
            Deleting...
          </Button>
        );
      }
      return (
        <tr key={query.id}>
          <td>{creationDate.toLocaleString()}</td>
          <td>{query.base.kind}</td>
          <td>{deleteBtn}</td>
        </tr>
      );
    });
  };

  const fetchQueryPage = async (nb: number) => {
    setQueryPageFetching(true);
    await doGet<Page<Query>>(
      "query",
      {
        limit: LIMIT,
        offset: (nb - 1) * LIMIT,
      },
      ctx
    )
      .then((page) => {
        const maxNb = Math.max(1, Math.ceil(page.total / LIMIT));
        if (nb > maxNb) {
          return fetchQueryPage(maxNb);
        } else {
          setQueryPage(page);
          setQueryPageNb(nb);
          setParams({
            ...params,
            queryPage: "1",
          });
        }
      })
      .catch((err) => {
        if (err === HttpError.Unauthorized) {
          navigate("/");
        } else {
          ctx.setError(Error.Unexpected);
        }
      })
      .finally(() => {
        setQueryPageFetching(false);
      });
  };

  useEffect(() => {
    (async function () {
      await fetchQueryPage(queryPageNb);
    })();
  }, []);

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
        {/* <Row>{table}</Row> */}
        <Row>
          <Table
            buildTrs={buildQueryTrs}
            fetching={queryPageFetching}
            page={queryPage}
            pageNb={queryPageNb}
            pageNbChanged={fetchQueryPage}
            pageSize={LIMIT}
            thead={queryTableThead}
          />
        </Row>
      </Container>
    </>
  );
}

function pageNumberFromQuery(key: string, params: URLSearchParams): number {
  let param = params.get(key);
  if (param == null) {
    param = "1";
  }
  try {
    return parseInt(param);
  } catch {
    return 1;
  }
}
