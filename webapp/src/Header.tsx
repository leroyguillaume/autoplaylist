import { faRightFromBracket } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { useContext } from "react";
import { Button, Container, Nav, Navbar } from "react-bootstrap";
import { Link, useNavigate } from "react-router-dom";
import Alert from "./Alert";
import { JWT_LOCAL_STORAGE_KEY } from "./api";
import { Context } from "./ctx";
import { Role } from "./domain";
import logo from "./logo.webp";

export default function Header() {
  const ctx = useContext(Context);

  const naviage = useNavigate();

  const logOut = () => {
    localStorage.removeItem(JWT_LOCAL_STORAGE_KEY);
    ctx.setAuthUser(null);
    naviage("/");
  };

  let syncLink = <></>;
  if (ctx.authUser?.role === Role.Admin) {
    syncLink = (
      <Nav.Link as={Link} to="/admin/sync">
        Sync
      </Nav.Link>
    );
  }

  return (
    <>
      <Navbar expand="md">
        <Container fluid>
          <Navbar.Brand as={Link} to="/home">
            <img
              className="d-inline-block align-top inline"
              src={logo}
              height="30"
            />
            AutoPlaylist
          </Navbar.Brand>
          <Navbar.Toggle aria-controls="menu" />
          <Navbar.Collapse id="menu">
            <Nav className="me-auto">
              <Nav.Link as={Link} to="/home">
                Home
              </Nav.Link>
              {syncLink}
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
      <Alert />
    </>
  );
}
