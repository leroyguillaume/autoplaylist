import { faSpinner, faTrash } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { useContext, useEffect, useState } from "react";
import { Button } from "react-bootstrap";
import { useNavigate } from "react-router-dom";
import Table from "./Table";
import { doDelete, doGet, handleCommonErrors } from "./api";
import { Context, Info } from "./ctx";
import { Page, Query } from "./domain";

const LIMIT = 10;

interface Props {
  initialPageNb: number;
  pageNbChanged: (nb: number) => void;
}

export default function QueryTable(props: Props) {
  const ctx = useContext(Context);

  const navigate = useNavigate();

  const [fetching, setFetching] = useState(false);
  const [inDeletion, setInDeletion] = useState<string[]>([]);
  const [page, setPage] = useState<Page<Query> | null>(null);
  const [pageNb, setPageNb] = useState(props.initialPageNb);

  const thead = (
    <thead>
      <tr>
        <th>Creation date</th>
        <th>Base</th>
        <th>Action</th>
      </tr>
    </thead>
  );

  const buildTrs = (page: Page<Query>) => {
    return page.content.map((query) => {
      const creationDate = new Date(query.creationDate);
      let deleteBtn;
      if (inDeletion.indexOf(query.id) === -1) {
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

  const deleteQuery = async (id: string) => {
    setInDeletion([...inDeletion, id]);
    await doDelete(`query/${id}`, ctx)
      .then(() => {
        ctx.setInfo(Info.QueryDeleted);
      })
      .catch((err) => {
        handleCommonErrors(err, ctx, navigate);
      })
      .then(() => fetchPage(pageNb));
  };

  const fetchPage = async (nb: number) => {
    setFetching(true);
    setInDeletion([]);
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
          return fetchPage(maxNb);
        } else {
          setPage(page);
          setPageNb(nb);
          props.pageNbChanged(nb);
        }
      })
      .catch((err) => {
        handleCommonErrors(err, ctx, navigate);
      })
      .finally(() => {
        setFetching(false);
      });
  };

  useEffect(() => {
    (async function () {
      await fetchPage(pageNb);
    })();
  }, []);

  return (
    <Table
      buildTrs={buildTrs}
      fetching={fetching}
      page={page}
      pageNb={pageNb}
      pageNbChanged={fetchPage}
      pageSize={LIMIT}
      thead={thead}
    />
  );
}
