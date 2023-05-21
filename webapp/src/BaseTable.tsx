import { faRotate } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { useContext, useEffect, useState } from "react";
import { Button } from "react-bootstrap";
import { useNavigate } from "react-router-dom";
import Table from "./Table";
import { doGet, doPut, handleCommonErrors } from "./api";
import { Context, Info } from "./ctx";
import { Base, Page, Role, SyncState } from "./domain";

const LIMIT = 5;

interface Props {
  initialPageNb: number;
  pageNbChanged: (nb: number) => void;
}

export default function PlaylistTable(props: Props) {
  const ctx = useContext(Context);

  const navigate = useNavigate();

  const [fetching, setFetching] = useState(false);
  const [inSync, setInSync] = useState<string[]>([]);
  const [page, setPage] = useState<Page<Base> | null>(null);
  const [pageNb, setPageNb] = useState(props.initialPageNb);

  let thead;
  if (ctx.authUser?.role === Role.Admin) {
    thead = (
      <thead>
        <tr>
          <th>Name</th>
          <th>Status</th>
          <th>Action</th>
        </tr>
      </thead>
    );
  } else {
    thead = (
      <thead>
        <tr>
          <th>Name</th>
          <th>Status</th>
        </tr>
      </thead>
    );
  }

  const buildTrs = (page: Page<Base>) => {
    return page.content.map((base) => {
      let status;
      let syncBtnDisabled = false;
      if (base.sync.state === SyncState.Running) {
        status = "synchronizing";
        syncBtnDisabled = true;
      } else {
        const lastSuccessDate = base.sync.lastSuccessDate;
        if (lastSuccessDate === null) {
          status = "never synchronized";
        } else {
          const date = new Date(lastSuccessDate).toLocaleString();
          status = `synchronized at ${date}`;
        }
      }
      let syncBtn;
      if (inSync.indexOf(base.id) === -1) {
        syncBtn = (
          <Button
            className="btn-sm"
            variant="secondary"
            onClick={() => sync(base.id)}
            disabled={syncBtnDisabled}
          >
            <FontAwesomeIcon icon={faRotate} className="inline" />
            Synchronize
          </Button>
        );
      } else {
        syncBtn = (
          <Button
            className="btn-sm"
            variant="secondary"
            onClick={() => sync(base.id)}
            disabled={true}
          >
            <FontAwesomeIcon icon={faRotate} className="inline" spin />
            Starting synchronization...
          </Button>
        );
      }
      if (ctx.authUser?.role === Role.Admin) {
        return (
          <tr key={base.id}>
            <td>{base.kind}</td>
            <td>{status}</td>
            <td>{syncBtn}</td>
          </tr>
        );
      } else {
        return (
          <tr key={base.id}>
            <td>{base.kind}</td>
            <td>{status}</td>
          </tr>
        );
      }
    });
  };

  const fetchPage = async (nb: number) => {
    setFetching(true);
    setInSync([]);
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
        handleCommonErrors(err, ctx, navigate);
      })
      .finally(() => {
        setFetching(false);
      });
  };

  const sync = async (id: string) => {
    setInSync([...inSync, id]);
    await doPut(`base/${id}`, null, ctx)
      .then(() => {
        ctx.setInfo(Info.BaseSyncWillStart);
      })
      .catch((err) => {
        handleCommonErrors(err, ctx, navigate);
      })
      .then(() => fetchPage(pageNb));
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
