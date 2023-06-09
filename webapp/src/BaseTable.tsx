import { faRotate, faSpinner } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { Button, Table } from "react-bootstrap";
import Pagination from "./Pagination";
import { Base, Page, SyncState } from "./domain";

interface Props {
  fetching: boolean;
  handleSync: (id: string) => void;
  page: Page<Base> | null;
  pageChanged: (nb: number) => void;
  pageNb: number | null;
  pageSize: number;
}

export default function BaseTable(props: Props) {
  const trs = props.page?.content.map((base) => {
    let lastSuccessDate = null;
    if (base.sync?.lastSuccessDate) {
      lastSuccessDate = new Date(base.sync?.lastSuccessDate!!).toLocaleString();
    }
    return (
      <tr key={base.id}>
        <td>{base.kind}</td>
        <td>{base.sync?.state}</td>
        <td>{lastSuccessDate}</td>
        <td>{base.sync?.lastErrMsg}</td>
        <td>
          <Button
            className="btn-sm"
            variant="secondary"
            onClick={() => props.handleSync(base.id)}
            disabled={base.sync?.state === SyncState.Running}
          >
            <FontAwesomeIcon icon={faRotate} className="inline" />
            Synchronize
          </Button>
        </td>
      </tr>
    );
  });
  let table;
  if (props.page === null || props.pageNb === null || props.fetching) {
    table = <FontAwesomeIcon icon={faSpinner} spin size="2x" />;
  } else {
    table = (
      <>
        <Table bordered>
          <thead>
            <tr>
              <th>Name</th>
              <th>Status</th>
              <th>Last success</th>
              <th>Last error message</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>{trs}</tbody>
        </Table>
        <Pagination
          nb={props.pageNb}
          size={props.pageSize}
          pageChanged={props.pageChanged}
          total={props.page.total}
        />
      </>
    );
  }

  return <div className="text-center">{table}</div>;
}
