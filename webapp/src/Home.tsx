import { faPlus } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { useContext, useEffect, useState } from "react";
import { Container, Row } from "react-bootstrap";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import Header from "./Header";
import PlaylistTable from "./PlaylistTable";
import { doDelete, doGet, handleCommonErrors } from "./api";
import { Context, pageNumberFromPlaylist } from "./ctx";
import { Page, Playlist } from "./domain";

const PLAYLIST_PAGE_SIZE = 10;

export default function Home() {
  const ctx = useContext(Context);

  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();

  const initialPlaylistPageNb = pageNumberFromPlaylist("playlistPage", params);
  const [playlistPage, setPlaylistPage] = useState<Page<Playlist> | null>(null);
  const [playlistPageNb, setPlaylistPageNb] = useState(initialPlaylistPageNb);
  const [fetchingPlaylistPage, setFetchingPlaylistPage] = useState(false);

  const deletePlaylist = async (id: string) => {
    setFetchingPlaylistPage(true);
    await doDelete(`playlist/${id}`, ctx)
      .then(() => fetchPlaylistPage(playlistPageNb))
      .catch((err) => {
        handleCommonErrors(err, ctx, navigate);
      })
      .finally(() => {
        setFetchingPlaylistPage(false);
      });
  };

  const fetchPlaylistPage = async (nb: number) => {
    setFetchingPlaylistPage(true);
    await doGet<Page<Playlist>>(
      "playlist",
      {
        limit: PLAYLIST_PAGE_SIZE,
        offset: (nb - 1) * PLAYLIST_PAGE_SIZE,
      },
      ctx
    )
      .then((page) => {
        const maxNb = Math.max(1, Math.ceil(page.total / PLAYLIST_PAGE_SIZE));
        if (nb > maxNb) {
          return fetchPlaylistPage(maxNb);
        } else {
          setPlaylistPage(page);
          setPlaylistPageNb(nb);
          setParams({
            playlistPage: nb.toString(),
          });
        }
      })
      .catch((err) => {
        handleCommonErrors(err, ctx, navigate);
      })
      .finally(() => {
        setFetchingPlaylistPage(false);
      });
  };

  useEffect(() => {
    (async function () {
      await fetchPlaylistPage(playlistPageNb);
    })();
  }, []);

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
            fetching={fetchingPlaylistPage}
            handleDelete={deletePlaylist}
            page={playlistPage}
            pageChanged={fetchPlaylistPage}
            pageNb={playlistPageNb}
            pageSize={PLAYLIST_PAGE_SIZE}
          />
        </Row>
      </Container>
    </>
  );
}
