import { faPlus } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { useState } from "react";
import { Container, Row } from "react-bootstrap";
import { Link, useSearchParams } from "react-router-dom";
import BaseTable from "./BaseTable";
import Header from "./Header";
import PlaylistTable from "./PlaylistTable";
import { pageNumberFromPlaylist } from "./ctx";

export default function Home() {
  const [params, setParams] = useSearchParams();

  const initialPlaylistPageNb = pageNumberFromPlaylist("playlistPage", params);
  const initialBasePageNb = pageNumberFromPlaylist("basePage", params);

  const [playlistPageNb, setPlaylistPageNb] = useState(initialPlaylistPageNb);
  const [basePageNb, setBasePageNb] = useState(initialBasePageNb);

  const updateBasePageParam = (nb: number) => {
    setBasePageNb(nb);
    setParams({
      basePage: nb.toString(),
      playlistPage: playlistPageNb.toString(),
    });
  };

  const updatePlaylistPageParam = (nb: number) => {
    setPlaylistPageNb(nb);
    setParams({
      basePage: basePageNb.toString(),
      playlistPage: nb.toString(),
    });
  };

  return (
    <>
      <Header />
      <Container>
        <Row>
          <div className="d-flex">
            <h3 className="col-8">My playlists</h3>
            <div className="col-4 text-end">
              <Link className="btn btn-primary" to="/playlist">
                <FontAwesomeIcon className="inline" icon={faPlus} />
                Add playlist
              </Link>
            </div>
          </div>
        </Row>
        <Row>
          <p>
            <em>All your playlists managed by AutoPlaylist.</em>
          </p>
        </Row>
        <Row>
          <PlaylistTable
            initialPageNb={initialPlaylistPageNb}
            pageNbChanged={updatePlaylistPageParam}
          />
        </Row>
        <Row>
          <div className="d-flex">
            <h3>Synchronized bases</h3>
          </div>
        </Row>
        <Row>
          <p>
            <em>
              A base can be your liked songs or a playlist on which you want as
              base of a playlist.
            </em>
          </p>
        </Row>
        <Row>
          <BaseTable
            initialPageNb={initialBasePageNb}
            pageNbChanged={updateBasePageParam}
          />
        </Row>
      </Container>
    </>
  );
}
