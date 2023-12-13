import React, { type FormEvent, useState, useContext } from "react";
import { Button, Col, Container, Form, FormSelect, Row } from "react-bootstrap";
import { t } from "i18next";
import { AppContext, type AppError, AppInfo } from ".";
import { useNavigate } from "react-router-dom";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faSpinner } from "@fortawesome/free-solid-svg-icons";
import { handleError } from "./utils";
import { Role, updateUser, type User } from "./api";

interface Props {
  className?: string;
  usr: User;
}

interface UserFields {
  role: Role;
}

function UserForm(props: Props): JSX.Element {
  const state = useContext(AppContext);

  const navigate = useNavigate();

  const [fields, setFields] = useState<UserFields>(userFields(props.usr));
  const [updating, setUpdating] = useState(false);
  const [validated, setValidated] = useState(false);

  const update = (evt: FormEvent<HTMLFormElement>): void => {
    evt.preventDefault();
    evt.stopPropagation();
    setValidated(true);
    const form = evt.currentTarget;
    if (form !== null && form.checkValidity()) {
      const usr = {
        ...props.usr,
        role: fields.role,
      };
      setUpdating(true);
      updateUser(props.usr.id, usr)
        .then((usr) => {
          state.setInfo(AppInfo.UserUpdated);
          setFields(userFields(usr));
        })
        .catch((err: AppError) => {
          handleError(err, state, navigate);
        })
        .finally(() => {
          setUpdating(false);
        });
    }
  };

  let submitBtn;
  if (updating) {
    submitBtn = (
      <Button type="submit" disabled>
        <FontAwesomeIcon icon={faSpinner} spin className="inline-icon" />
        {t("label.updating")}
        {t("punctuation.ellipsis")}
      </Button>
    );
  } else {
    submitBtn = <Button type="submit">{t("label.update")}</Button>;
  }

  return (
    <>
      <Container className={props.className}>
        <Form noValidate validated={validated} onSubmit={update}>
          <Row>
            <Col>
              <Form.Group className="mb-3">
                <Form.Label>{t("label.role")}</Form.Label>
                <FormSelect
                  defaultValue={fields?.role ?? Role.User}
                  onChange={(evt) => {
                    setFields({ ...fields, role: evt.target.value as Role });
                  }}
                >
                  <option value={Role.User}>{t("role.user")}</option>
                  <option value={Role.Admin}>{t("role.admin")}</option>
                </FormSelect>
              </Form.Group>
            </Col>
          </Row>
          <Row>
            <Col>{submitBtn}</Col>
          </Row>
        </Form>
      </Container>
    </>
  );
}

export default UserForm;

function userFields(usr: User): UserFields {
  return {
    role: usr.role ?? Role.User,
  };
}
