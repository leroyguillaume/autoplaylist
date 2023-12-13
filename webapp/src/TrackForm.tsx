import React, { type FormEvent, useState, useContext } from "react";
import { Button, Col, Container, Form, Row } from "react-bootstrap";
import { t } from "i18next";
import { type Track, updateTrack } from "./api";
import { AppContext, type AppError, AppInfo } from ".";
import { useLocation, useNavigate } from "react-router-dom";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faSpinner } from "@fortawesome/free-solid-svg-icons";
import { backPath, handleError } from "./utils";

interface TrackFields {
  album: string;
  compil: boolean;
  artists: string;
  title: string;
  year: number;
}

interface Props {
  track: Track;
}

function TrackForm(props: Props): JSX.Element {
  const state = useContext(AppContext);

  const navigate = useNavigate();
  const loc = useLocation();

  const [fields, setFields] = useState(trackFields(props.track));
  const [validated, setValidated] = useState(false);
  const [processing, setProcessing] = useState(false);

  const update = (evt: FormEvent<HTMLFormElement>): void => {
    evt.preventDefault();
    evt.stopPropagation();
    setValidated(true);
    const form = evt.currentTarget;
    if (form !== null && form.checkValidity()) {
      setProcessing(true);
      const update = {
        album: {
          compil: fields.compil,
          name: fields.album,
        },
        artists: fields.artists.split(","),
        title: fields.title,
        year: fields.year,
      };
      updateTrack(props.track.id, update)
        .then(() => {
          state.setInfo(AppInfo.TrackUpdated);
          navigate(backPath(loc));
        })
        .catch((err: AppError) => {
          handleError(err, state, navigate);
        })
        .finally(() => {
          setProcessing(false);
        });
    }
  };

  let submitBtn;
  if (processing) {
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
      <Container>
        <Form noValidate validated={validated} onSubmit={update}>
          <Row>
            <Col>
              <Form.Group className="mb-2">
                <Form.Label>{t("label.title")}</Form.Label>
                <Form.Control
                  type="text"
                  placeholder={t("placeholder.title")}
                  required
                  defaultValue={fields.title}
                  onChange={(evt) => {
                    setFields({ ...fields, title: evt.target.value });
                  }}
                />
                <Form.Control.Feedback type="invalid">
                  {t("validation.title")}
                </Form.Control.Feedback>
              </Form.Group>
            </Col>
          </Row>
          <Row>
            <Col>
              <Form.Group className="mb-2">
                <Form.Label>{t("label.artists")}</Form.Label>
                <Form.Control
                  type="text"
                  placeholder={t("placeholder.artists")}
                  required
                  defaultValue={fields.artists}
                  onChange={(evt) => {
                    setFields({ ...fields, artists: evt.target.value });
                  }}
                />
                <Form.Control.Feedback type="invalid">
                  {t("validation.artists")}
                </Form.Control.Feedback>
              </Form.Group>
            </Col>
          </Row>
          <Row>
            <Col>
              <Form.Group className="mb-2">
                <Form.Label>{t("label.album")}</Form.Label>
                <Form.Control
                  type="text"
                  placeholder={t("placeholder.album")}
                  required
                  defaultValue={fields.album}
                  onChange={(evt) => {
                    setFields({ ...fields, album: evt.target.value });
                  }}
                  className="mb-2"
                />
                <Form.Check
                  type="checkbox"
                  defaultChecked={fields.compil}
                  label={t("label.compil")}
                  onChange={(evt) => {
                    setFields({ ...fields, compil: evt.target.checked });
                  }}
                />
                <Form.Control.Feedback type="invalid">
                  {t("validation.album")}
                </Form.Control.Feedback>
              </Form.Group>
            </Col>
          </Row>
          <Row>
            <Col>
              <Form.Group className="mb-3">
                <Form.Label>{t("label.year")}</Form.Label>
                <Form.Control
                  type="number"
                  placeholder={t("placeholder.year")}
                  required
                  defaultValue={fields.year}
                  onChange={(evt) => {
                    setFields({ ...fields, year: Number(evt.target.value) });
                  }}
                />
                <Form.Control.Feedback type="invalid">
                  {t("validation.album")}
                </Form.Control.Feedback>
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

export default TrackForm;

function trackFields(track: Track): TrackFields {
  return {
    album: track.album.name,
    artists: track.artists.join(", "),
    compil: track.album.compil,
    title: track.title,
    year: track.year,
  };
}
