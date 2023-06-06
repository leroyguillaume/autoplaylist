import { faPlus } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { useState } from "react";
import { Container, Row } from "react-bootstrap";
import { Link, useSearchParams } from "react-router-dom";
import Header from "./Header";
import PlaylistTable from "./PlaylistTable";
import { pageNumberFromPlaylist } from "./ctx";

export default function Home() {
  const [params, setParams] = useSearchParams();

  const initialPlaylistPageNb = pageNumberFromPlaylist("playlistPage", params);

  const [_, setPlaylistPageNb] = useState(initialPlaylistPageNb);

  const updatePlaylistPageParam = (nb: number) => {
    setPlaylistPageNb(nb);
    setParams({
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
      </Container>
    </>
  );
}
