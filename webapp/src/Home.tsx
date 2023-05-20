import { faPlus } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { Container, Row } from "react-bootstrap";
import { Link } from "react-router-dom";
import Header from "./Header";
import QueryTable from "./QueryTable";

export default function Home() {
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
          <QueryTable paramKey="queryPage" />
        </Row>
      </Container>
    </>
  );
}
