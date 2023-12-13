import React, { useContext, useEffect, useState } from "react";
import {
  Button,
  Col,
  Container,
  FormControl,
  Row,
  Table,
} from "react-bootstrap";
import { t } from "i18next";
import {
  type Page,
  type PageRequest,
  deleteUser,
  type User,
  users,
} from "./api";
import {
  AppContext,
  AppInfo,
  type AppError,
  LIMIT,
  PATH_ADMIN,
  PATH_USR,
} from ".";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import {
  faPencil,
  faSpinner,
  faTrash,
} from "@fortawesome/free-solid-svg-icons";
import Pagination from "./Pagination";
import { handleError, removeToken } from "./utils";
import { useLocation, useNavigate } from "react-router";
import { LinkContainer } from "react-router-bootstrap";
import ConfirmationModal from "./ConfirmationModal";

interface Props {
  name: string;
  page: number;
  onEmailChange: (name: string) => void;
  onPageChange: (page: number) => void;
}

function UsersTable(props: Props): JSX.Element {
  const state = useContext(AppContext);

  const navigate = useNavigate();
  const loc = useLocation();

  const [page, setPage] = useState<Page<User> | null>(null);
  const [req, setReq] = useState<PageRequest>({
    limit: LIMIT,
    offset: LIMIT * (props.page - 1),
  });
  const [email, setEmail] = useState(props.name);

  const [refreshing, setRefreshing] = useState<boolean>(true);
  const [deleting, setDeleting] = useState<boolean>(false);
  const [id, setId] = useState<string | null>(null);

  const refresh = (): void => {
    setRefreshing(true);
    users(req, email)
      .then((page) => {
        setPage(page);
        props.onPageChange(page.req.offset / page.req.limit + 1);
      })
      .catch((err: AppError) => {
        handleError(err, state, navigate);
      })
      .finally(() => {
        setRefreshing(false);
      });
  };

  const remove = (): void => {
    if (id !== null) {
      setDeleting(true);
      void deleteUser(id)
        .catch((err: AppError) => {
          handleError(err, state, navigate);
        })
        .then(() => {
          setId(null);
          if (id === state.auth?.id) {
            removeToken(state);
            navigate("/");
          } else {
            state.setInfo(AppInfo.UserDeleted);
            refresh();
          }
        })
        .finally(() => {
          setDeleting(false);
        });
    }
  };

  const updateEmail = (email: string): void => {
    setEmail(email);
    props.onEmailChange(email);
  };

  useEffect(() => {
    const id = setTimeout(refresh, 500);
    return () => {
      clearTimeout(id);
    };
  }, [email, req]);

  const trs = page?.items.map((usr: User) => {
    const emailLis: JSX.Element[] = [];
    if (usr.creds.spotify !== undefined) {
      emailLis.push(
        <li key="spotify">
          <a href={`https://open.spotify.com/user/${usr.creds.spotify.id}`}>
            Spotify{t("punctuation.colon")} {usr.creds.spotify.email}
          </a>
        </li>,
      );
    }

    return (
      <tr key={usr.id}>
        <td>
          <ul>{emailLis}</ul>
        </td>
        <td>{t(`role.${usr.role}`)}</td>
        <td className="text-center">
          <LinkContainer
            to={`${PATH_ADMIN}${PATH_USR}/${usr.id}`}
            state={{ history: [...(loc.state?.history ?? []), loc.pathname] }}
          >
            <Button as="a" variant="primary" className="me-1 mb-1 mb-lg-0">
              <FontAwesomeIcon icon={faPencil} />
            </Button>
          </LinkContainer>
          <Button
            variant="danger"
            onClick={() => {
              setId(usr.id);
            }}
            className="mb-1 mb-lg-0"
          >
            <FontAwesomeIcon icon={faTrash} />
          </Button>
        </td>
      </tr>
    );
  });
  let table = <></>;
  if (refreshing) {
    table = (
      <Row>
        <Col>
          <FontAwesomeIcon icon={faSpinner} spin />
        </Col>
      </Row>
    );
  } else if (page !== null) {
    table = (
      <>
        <Row className="mb-3">
          <Col xs={12} lg={{ span: 6, offset: 6 }} xl={{ span: 4, offset: 8 }}>
            <FormControl
              defaultValue={email}
              type="text"
              placeholder={t("placeholder.search")}
              onChange={(evt) => {
                updateEmail(evt.target.value);
              }}
              autoFocus
            />
          </Col>
        </Row>
        <Row className="mb-3 mb-sm-0">
          <Col>
            <Table striped bordered hover responsive>
              <thead className="text-center">
                <tr>
                  <th>{t("label.email")}</th>
                  <th>{t("label.role")}</th>
                  <th>{t("label.actions")}</th>
                </tr>
              </thead>
              <tbody>{trs}</tbody>
            </Table>
          </Col>
        </Row>
        <Pagination
          req={req}
          total={page.total}
          onChange={(req) => {
            setRefreshing(true);
            setReq(req);
          }}
        />
      </>
    );
  }

  return (
    <>
      <ConfirmationModal
        deleting={deleting}
        show={id !== null}
        onCancel={() => {
          setId(null);
        }}
        onConfirm={remove}
        text="paragraph.delete-user"
      />
      <Container>{table}</Container>
    </>
  );
}

export default UsersTable;
