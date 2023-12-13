import React, { type FormEvent, useState, useContext } from "react";
import { Button, Col, Container, Form, Row } from "react-bootstrap";
import { t } from "i18next";
import PredicateControl from "./PredicateControl";
import {
  createPlaylist,
  type SourceKind,
  type Predicate,
  type Playlist,
  updatePlaylist,
} from "./api";
import { AppContext, type AppError, AppInfo } from ".";
import { useLocation, useNavigate } from "react-router-dom";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faSpinner } from "@fortawesome/free-solid-svg-icons";
import { backPath, handleError } from "./utils";
import PlaylistIdControl from "./PlaylistIdControl";

interface PlaylistFields {
  name: string;
  predicate: Predicate;
  src: SourceKind;
}

interface Props {
  playlist?: Playlist;
}

enum SourceOption {
  SpotifyPlaylist = "spotify-playlist",
  SpotifySavedTracks = "spotify-saved-tracks",
}

function PlaylistForm(props: Props): JSX.Element {
  const state = useContext(AppContext);

  const navigate = useNavigate();
  const loc = useLocation();

  const [fields, setFields] = useState(playlistFields(props.playlist));
  const [validated, setValidated] = useState(false);
  const [processing, setProcessing] = useState(false);

  const createOrUpdate = (evt: FormEvent<HTMLFormElement>): void => {
    evt.preventDefault();
    evt.stopPropagation();
    setValidated(true);
    const form = evt.currentTarget;
    if (form !== null && form.checkValidity()) {
      setProcessing(true);
      let promise;
      if (props.playlist === undefined) {
        const creation = {
          name: fields.name,
          predicate: fields.predicate,
          src: fields.src,
        };
        promise = createPlaylist(creation);
      } else {
        const update = {
          name: fields.name,
          predicate: fields.predicate,
        };
        promise = updatePlaylist(props.playlist.id, update);
      }
      promise
        .then(() => {
          state.setInfo(
            props.playlist === undefined
              ? AppInfo.PlaylistCreated
              : AppInfo.PlaylistUpdated,
          );
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

  const updateSource = (opt: SourceOption): void => {
    switch (opt) {
      case SourceOption.SpotifyPlaylist:
        setFields({ ...fields, src: { spotify: { playlist: "" } } });
        break;
      case SourceOption.SpotifySavedTracks:
        setFields({ ...fields, src: { spotify: "savedTracks" } });
        break;
    }
  };

  let defaultSrcOpt = SourceOption.SpotifySavedTracks;
  let playlistIdControl = <></>;
  if (
    typeof fields.src.spotify === "object" &&
    "playlist" in fields.src.spotify
  ) {
    defaultSrcOpt = SourceOption.SpotifyPlaylist;
    playlistIdControl = (
      <Row>
        <Col>
          <Form.Group className="mb-2">
            <Form.Label>{t("label.playlist-name")}</Form.Label>
            <PlaylistIdControl
              onPlaylistIdChange={(id) => {
                setFields({ ...fields, src: { spotify: { playlist: id } } });
              }}
              disabled={props.playlist !== undefined}
              id={fields.src.spotify.playlist}
            />
            <Form.Control.Feedback type="invalid">
              {t("validation.playlist-name")}
            </Form.Control.Feedback>
          </Form.Group>
        </Col>
      </Row>
    );
  }

  let submitBtn;
  if (props.playlist !== undefined) {
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
  } else {
    if (processing) {
      submitBtn = (
        <Button type="submit" disabled>
          <FontAwesomeIcon icon={faSpinner} spin className="inline-icon" />
          {t("label.creating")}
          {t("punctuation.ellipsis")}
        </Button>
      );
    } else {
      submitBtn = <Button type="submit">{t("label.create")}</Button>;
    }
  }

  return (
    <>
      <Container>
        <Form noValidate validated={validated} onSubmit={createOrUpdate}>
          <Row>
            <Col>
              <Form.Group className="mb-2">
                <Form.Label>{t("label.name")}</Form.Label>
                <Form.Control
                  type="text"
                  placeholder={t("placeholder.name")}
                  maxLength={100}
                  required
                  defaultValue={fields.name}
                  onChange={(evt) => {
                    setFields({ ...fields, name: evt.target.value });
                  }}
                />
                <Form.Control.Feedback type="invalid">
                  {t("validation.name")}
                </Form.Control.Feedback>
              </Form.Group>
            </Col>
          </Row>
          <Row>
            <Col>
              <Form.Group className="mb-2">
                <Form.Label>{t("label.source")}</Form.Label>
                <Form.Select
                  onChange={(evt) => {
                    updateSource(evt.target.value as SourceOption);
                  }}
                  defaultValue={defaultSrcOpt}
                  disabled={props.playlist !== undefined}
                >
                  <option value={SourceOption.SpotifySavedTracks}>
                    {t("label.spotify-saved-tracks")}
                  </option>
                  <option value={SourceOption.SpotifyPlaylist}>
                    {t("label.spotify-playlist")}
                  </option>
                </Form.Select>
              </Form.Group>
            </Col>
          </Row>
          {playlistIdControl}
          <Row>
            <Col>
              <Form.Group className="mb-3">
                <Form.Label>{t("label.filter")}</Form.Label>
                <PredicateControl
                  predicate={fields.predicate}
                  onChange={(predicate) => {
                    setFields({ ...fields, predicate });
                  }}
                />
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

export default PlaylistForm;

function playlistFields(playlist?: Playlist): PlaylistFields {
  return {
    name: playlist?.name ?? "",
    predicate: playlist?.predicate ?? { artistsAre: [] },
    src: playlist?.src.kind ?? { spotify: "savedTracks" },
  };
}
