import { faSpinner, faTrash } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { Button, Table } from "react-bootstrap";
import Pagination from "./Pagination";
import { Page, Playlist, SyncState } from "./domain";

interface Props {
  fetching: boolean;
  handleDelete: (id: string) => void;
  page: Page<Playlist> | null;
  pageChanged: (nb: number) => void;
  pageNb: number | null;
  pageSize: number;
}

export default function PlaylistTable(props: Props) {
  const trs = props.page?.content.map((playlist) => {
    const creationDate = new Date(playlist.creationDate);
    let syncState;
    if (playlist.sync) {
      if (playlist.sync.state === SyncState.Running) {
        syncState = "synchronization in progress...";
      } else if (playlist.sync.lastSuccessDate) {
        const lastSuccessDate = new Date(playlist.sync.lastSuccessDate);
        syncState = `synchronized at ${lastSuccessDate.toLocaleString()}`;
      }
    } else {
      syncState = "synchornization will start in few minutes!";
    }
    return (
      <tr key={playlist.id}>
        <td>{playlist.name}</td>
        <td>{creationDate.toLocaleString()}</td>
        <td>{syncState}</td>
        <td>
          <Button
            className="btn-sm"
            variant="danger"
            onClick={() => props.handleDelete(playlist.id)}
          >
            <FontAwesomeIcon icon={faTrash} className="inline" />
            Delete
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
              <th>Creation date</th>
              <th>Status</th>
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
