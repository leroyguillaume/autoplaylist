import { faRightFromBracket } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { Button, Container, Nav, Navbar } from "react-bootstrap";
import { Link, useNavigate } from "react-router-dom";
import { JWT_LOCAL_STORAGE_KEY } from "./api";

export default function Header() {
  const naviage = useNavigate();

  const logOut = () => {
    localStorage.removeItem(JWT_LOCAL_STORAGE_KEY);
    naviage("/");
  };

  return (
    <>
      <Navbar expand="md">
        <Container fluid>
          <Navbar.Brand as={Link} to="/home">
            AutoPlaylist
          </Navbar.Brand>
          <Navbar.Toggle aria-controls="menu" />
          <Navbar.Collapse id="menu">
            <Nav className="me-auto">
              <Nav.Link as={Link} to="/home">
                Home
              </Nav.Link>
            </Nav>
            <Nav className="d-flex">
              <Button variant="secondary" onClick={logOut}>
                <FontAwesomeIcon className="inline" icon={faRightFromBracket} />
                Log-out
              </Button>
            </Nav>
          </Navbar.Collapse>
        </Container>
      </Navbar>
    </>
  );
}
