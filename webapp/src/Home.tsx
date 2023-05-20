import { faPlus } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { useState } from "react";
import { Container, Row } from "react-bootstrap";
import { Link, useSearchParams } from "react-router-dom";
import BaseTable from "./BaseTable";
import Header from "./Header";
import QueryTable from "./QueryTable";
import { pageNumberFromQuery } from "./ctx";

export default function Home() {
  const [params, setParams] = useSearchParams();

  const initialQueryPageNb = pageNumberFromQuery("queryPage", params);
  const initialBasePageNb = pageNumberFromQuery("basePage", params);

  const [queryPageNb, setQueryPageNb] = useState(initialQueryPageNb);
  const [basePageNb, setBasePageNb] = useState(initialBasePageNb);

  const updateBasePageParam = (nb: number) => {
    setBasePageNb(nb);
    setParams({
      basePage: nb.toString(),
      queryPage: queryPageNb.toString(),
    });
  };

  const updateQueryPageParam = (nb: number) => {
    setQueryPageNb(nb);
    setParams({
      basePage: basePageNb.toString(),
      queryPage: nb.toString(),
    });
  };

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
        <Row>
          <QueryTable
            initialPageNb={initialQueryPageNb}
            pageNbChanged={updateQueryPageParam}
          />
        </Row>
        <Row>
          <div className="d-flex title">
            <h3>Synchronized bases</h3>
          </div>
        </Row>
        <Row>
          <BaseTable
            initialPageNb={initialBasePageNb}
            pageNbChanged={updateBasePageParam}
          />
        </Row>
      </Container>
    </>
  );
}
