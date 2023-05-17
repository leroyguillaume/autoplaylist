import { faPlus } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { Container, Row } from "react-bootstrap";
import { Link } from "react-router-dom";
import Header from "./Header";

export default function Home() {
  return (
    <>
      <Header />
      <Container>
        <Row>
          <h3 className="col-12 col-sm-8">My queries</h3>
          <div className="col-4 text-md-end text-sm-left">
            <Link className="btn btn-primary" to="/query">
              <FontAwesomeIcon className="inline" icon={faPlus} />
              Add query
            </Link>
          </div>
        </Row>
      </Container>
    </>
  );
}
