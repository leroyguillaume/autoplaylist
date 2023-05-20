import { useContext, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import Table from "./Table";
import { HttpError, doGet } from "./api";
import { Context, Error } from "./ctx";
import { Base, Page, SyncState } from "./domain";

const LIMIT = 5;

interface Props {
  initialPageNb: number;
  pageNbChanged: (nb: number) => void;
}

export default function QueryTable(props: Props) {
  const ctx = useContext(Context);

  const navigate = useNavigate();

  const [fetching, setFetching] = useState(false);
  const [page, setPage] = useState<Page<Base> | null>(null);
  const [pageNb, setPageNb] = useState(props.initialPageNb);

  const thead = (
    <thead>
      <tr>
        <th>Name</th>
        <th>Status</th>
      </tr>
    </thead>
  );

  const buildTrs = (page: Page<Base>) => {
    return page.content.map((base) => {
      let status;
      if (base.sync.state === SyncState.Running) {
        status = "synchronizing";
      } else {
        const lastSuccessDate = base.sync.lastSuccessDate;
        if (lastSuccessDate === null) {
          status = "never synchronized";
        } else {
          const date = new Date(lastSuccessDate).toLocaleString();
          status = `synchronized at ${date}`;
        }
      }
      return (
        <tr key={base.id}>
          <td>{base.kind}</td>
          <td>{status}</td>
        </tr>
      );
    });
  };

  const fetchPage = async (nb: number) => {
    setFetching(true);
    await doGet<Page<Base>>(
      "base",
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
        if (err === HttpError.Unauthorized) {
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
