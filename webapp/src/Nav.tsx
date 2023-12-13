import React, { useContext } from "react";
import {
  Container,
  Navbar,
  Nav as BootstrapNav,
  NavDropdown,
  Button,
} from "react-bootstrap";
import {
  AppContext,
  LOCAL_STORAGE_KEY_TOKEN,
  PATH_ADMIN,
  PATH_ME,
  PATH_PLAYLIST,
  PATH_SRC,
  PATH_TRACK,
  PATH_USR,
} from ".";
import { t } from "i18next";
import { useLocation, useNavigate } from "react-router-dom";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faArrowRightFromBracket } from "@fortawesome/free-solid-svg-icons";
import { LinkContainer } from "react-router-bootstrap";
import { Role } from "./api";

function Nav(): JSX.Element {
  const state = useContext(AppContext);

  const navigate = useNavigate();
  const loc = useLocation();

  const logout = (): void => {
    localStorage.removeItem(LOCAL_STORAGE_KEY_TOKEN);
    navigate("/");
  };

  let adminNav = <></>;
  if (state.auth?.role === Role.Admin) {
    adminNav = (
      <NavDropdown title={t("label.admin")}>
        <LinkContainer
          to={`${PATH_ADMIN}${PATH_PLAYLIST}`}
          state={{ history: [...(loc.state?.history ?? []), loc.pathname] }}
        >
          <NavDropdown.Item
            active={loc.pathname === `${PATH_ADMIN}${PATH_PLAYLIST}`}
          >
            {t("title.playlists")}
          </NavDropdown.Item>
        </LinkContainer>
        <LinkContainer
          to={`${PATH_ADMIN}${PATH_SRC}`}
          state={{ history: [...(loc.state?.history ?? []), loc.pathname] }}
        >
          <NavDropdown.Item
            active={loc.pathname === `${PATH_ADMIN}${PATH_SRC}`}
          >
            {t("title.sources")}
          </NavDropdown.Item>
        </LinkContainer>
        <LinkContainer
          to={`${PATH_ADMIN}${PATH_TRACK}`}
          state={{ history: [...(loc.state?.history ?? []), loc.pathname] }}
        >
          <NavDropdown.Item
            active={loc.pathname === `${PATH_ADMIN}${PATH_TRACK}`}
          >
            {t("title.tracks")}
          </NavDropdown.Item>
        </LinkContainer>
        <LinkContainer
          to={`${PATH_ADMIN}${PATH_USR}`}
          state={{ history: [...(loc.state?.history ?? []), loc.pathname] }}
        >
          <NavDropdown.Item
            active={loc.pathname === `${PATH_ADMIN}${PATH_USR}`}
          >
            {t("title.users")}
          </NavDropdown.Item>
        </LinkContainer>
      </NavDropdown>
    );
  }

  return (
    <Navbar className="mb-3" expand="lg">
      <Container>
        <LinkContainer
          to={PATH_PLAYLIST}
          state={{ history: [...(loc.state?.history ?? []), loc.pathname] }}
        >
          <Navbar.Brand>AutoPlaylist</Navbar.Brand>
        </LinkContainer>
        <Navbar.Toggle />
        <Navbar.Collapse>
          <BootstrapNav className="me-auto">
            <LinkContainer
              to={PATH_PLAYLIST}
              state={{ history: [...(loc.state?.history ?? []), loc.pathname] }}
            >
              <BootstrapNav.Link active={loc.pathname === PATH_PLAYLIST}>
                {t("title.my-playlists")}
              </BootstrapNav.Link>
            </LinkContainer>
            {adminNav}
          </BootstrapNav>
          <BootstrapNav>
            <LinkContainer
              to={PATH_ME}
              state={{ history: [...(loc.state?.history ?? []), loc.pathname] }}
            >
              <BootstrapNav.Link active={loc.pathname === PATH_ME}>
                {t("title.my-account")}
              </BootstrapNav.Link>
            </LinkContainer>
            <Button onClick={logout} variant="link" className="nav-link">
              <FontAwesomeIcon
                icon={faArrowRightFromBracket}
                className="inline-icon"
              />
              {t("label.logout")}
            </Button>
          </BootstrapNav>
        </Navbar.Collapse>
      </Container>
    </Navbar>
  );
}

export default Nav;
