import { faSpinner } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { ReactNode, useContext } from "react";
import { Pagination, Table as ReactTable } from "react-bootstrap";
import { Context } from "./ctx";
import { Page } from "./domain";

interface Props<T> {
  buildTrs: (page: Page<T>) => ReactNode;
  fetching: boolean;
  page: Page<T> | null;
  pageNb: number;
  pageNbChanged: (nb: number) => void;
  pageSize: number;
  thead: ReactNode;
}

export default function Table<T>(props: Props<T>) {
  const ctx = useContext(Context);

  if (props.page === null || props.fetching) {
    return (
      <div className="text-center">
        <FontAwesomeIcon icon={faSpinner} spin size="2x" />
      </div>
    );
  } else {
    const trs = props.buildTrs(props.page);
    const maxPageNb = Math.ceil(props.page.total / props.pageSize);
    let paginationFirst;
    let paginationPrev;
    let paginationNext;
    let paginationLast;
    if (props.pageNb <= 1) {
      paginationFirst = <></>;
      paginationPrev = <></>;
    } else {
      paginationFirst = (
        <Pagination.First onClick={() => props.pageNbChanged(1)} />
      );
      paginationPrev = (
        <Pagination.Prev
          onClick={() => props.pageNbChanged(props.pageNb - 1)}
        />
      );
    }
    if (props.pageNb >= maxPageNb) {
      paginationNext = <></>;
      paginationLast = <></>;
    } else {
      paginationNext = (
        <Pagination.Next
          onClick={() => props.pageNbChanged(props.pageNb + 1)}
        />
      );
      paginationLast = (
        <Pagination.Last onClick={() => props.pageNbChanged(maxPageNb)} />
      );
    }
    return (
      <div className="text-center">
        <ReactTable bordered>
          {props.thead}
          <tbody>{trs}</tbody>
        </ReactTable>
        <Pagination className="justify-content-end">
          {paginationFirst}
          {paginationPrev}
          {paginationNext}
          {paginationLast}
        </Pagination>
      </div>
    );
  }
}
