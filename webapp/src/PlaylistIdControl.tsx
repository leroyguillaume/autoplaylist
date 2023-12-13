import React, { useState, useContext, useEffect } from "react";
import { AppContext, type AppError } from ".";
import { useNavigate } from "react-router-dom";
import {
  type PlatformPlaylist,
  userSpotifyPlaylists,
  refreshUserSpotifyPlaylists,
  type Page,
} from "./api";
import { handleError } from "./utils";
import { Button, FormSelect, InputGroup } from "react-bootstrap";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faRotate, faSpinner } from "@fortawesome/free-solid-svg-icons";

interface Props {
  disabled?: boolean;
  id?: string;
  onPlaylistIdChange: (id: string) => void;
}

function PlaylistIdControl(props: Props): JSX.Element {
  const state = useContext(AppContext);

  const navigate = useNavigate();

  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState<Page<PlatformPlaylist> | null>(null);

  const load = (): void => {
    setLoading(true);
    const req = {
      offset: 0,
      limit: 100,
    };
    userSpotifyPlaylists(state.auth?.id ?? "", req)
      .then((page) => {
        setPage(page);
      })
      .catch((err: AppError) => {
        handleError(err, state, navigate);
      })
      .finally(() => {
        setLoading(false);
      });
  };

  const refresh = (): void => {
    setLoading(true);
    refreshUserSpotifyPlaylists(state.auth?.id ?? "")
      .then(() => {
        load();
      })
      .catch((err: AppError) => {
        handleError(err, state, navigate);
      })
      .finally(() => {
        setLoading(false);
      });
  };

  useEffect(() => {
    const id = setTimeout(load, 500);
    return () => {
      clearTimeout(id);
    };
  }, []);

  let refreshBtn;
  if (loading) {
    refreshBtn = (
      <Button variant="secondary" disabled>
        <FontAwesomeIcon icon={faRotate} spin />
      </Button>
    );
  } else {
    refreshBtn = (
      <Button variant="secondary" onClick={refresh} disabled={props.disabled}>
        <FontAwesomeIcon icon={faRotate} />
      </Button>
    );
  }

  let opts: JSX.Element[] = [];
  if (page !== null) {
    opts = page.items.map((playlist) => (
      <option key={playlist.id} value={playlist.id}>
        {playlist.name}
      </option>
    ));
  }

  let input;
  if (loading) {
    input = <FontAwesomeIcon icon={faSpinner} spin />;
  } else {
    input = (
      <>
        <FormSelect
          onChange={(evt) => {
            props.onPlaylistIdChange(evt.target.value);
          }}
          disabled={props.disabled}
          defaultValue={props.id}
        >
          {opts}
        </FormSelect>
        {refreshBtn}
      </>
    );
  }

  return <InputGroup>{input}</InputGroup>;
}

export default PlaylistIdControl;
