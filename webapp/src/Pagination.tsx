import { Pagination as BootstrapPagination } from "react-bootstrap";

interface Props {
  nb: number;
  pageChanged: (nb: number) => void;
  size: number;
  total: number;
}

export default function Pagination(props: Props) {
  const maxPageNb = Math.ceil(props.total / props.size);
  let paginationFirst;
  let paginationPrev;
  let paginationNext;
  let paginationLast;
  if (props.nb <= 1) {
    paginationFirst = <></>;
    paginationPrev = <></>;
  } else {
    paginationFirst = (
      <BootstrapPagination.First onClick={() => props.pageChanged(1)} />
    );
    paginationPrev = (
      <BootstrapPagination.Prev
        onClick={() => props.pageChanged(props.nb - 1)}
      />
    );
  }
  if (props.nb >= maxPageNb) {
    paginationNext = <></>;
    paginationLast = <></>;
  } else {
    paginationNext = (
      <BootstrapPagination.Next
        onClick={() => props.pageChanged(props.nb + 1)}
      />
    );
    paginationLast = (
      <BootstrapPagination.Last onClick={() => props.pageChanged(maxPageNb)} />
    );
  }

  return (
    <BootstrapPagination className="justify-content-end">
      {paginationFirst}
      {paginationPrev}
      {paginationNext}
      {paginationLast}
    </BootstrapPagination>
  );
}
