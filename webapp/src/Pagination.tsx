import React from "react";
import { Col, Pagination as BootstrapPagination, Row } from "react-bootstrap";
import { type PageRequest } from "./api";

interface Props {
  req: PageRequest;
  total: number;
  onChange: (req: PageRequest) => void;
}

function Pagination(props: Props): JSX.Element {
  const emitOnChange = (offset: number): void => {
    props.onChange({
      ...props.req,
      offset,
    });
  };

  let first = (
    <BootstrapPagination.First
      onClick={() => {
        emitOnChange(0);
      }}
    />
  );
  let prev = (
    <BootstrapPagination.Prev
      onClick={() => {
        emitOnChange(props.req.offset - props.req.limit);
      }}
    />
  );
  let next = (
    <BootstrapPagination.Next
      onClick={() => {
        emitOnChange(props.req.offset + props.req.limit);
      }}
    />
  );
  let last = (
    <BootstrapPagination.Last
      onClick={() => {
        emitOnChange(
          (Math.ceil(props.total / props.req.limit) - 1) * props.req.limit,
        );
      }}
    />
  );
  if (props.req.offset === 0) {
    first = <BootstrapPagination.First disabled />;
    prev = <BootstrapPagination.Prev disabled />;
  }
  if (props.req.offset + props.req.limit >= props.total) {
    next = <BootstrapPagination.Next disabled />;
    last = <BootstrapPagination.Last disabled />;
  }
  return (
    <Row>
      <Col>
        <BootstrapPagination>
          {first}
          {prev}
          {next}
          {last}
        </BootstrapPagination>
      </Col>
    </Row>
  );
}

export default Pagination;
