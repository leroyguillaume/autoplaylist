import React from "react";
import { t } from "i18next";
import { type SourceKind } from "./api";

interface Props {
  kind: SourceKind;
}

function SourceTd(props: Props): JSX.Element {
  let srcTd = <></>;
  if (props.kind.spotify === "savedTracks") {
    srcTd = <td>{t("label.spotify-saved-tracks")}</td>;
  } else if (
    typeof props.kind.spotify === "object" &&
    "playlist" in props.kind.spotify
  ) {
    srcTd = (
      <td>
        <a
          href={`https://open.spotify.com/playlist/${props.kind.spotify.playlist}`}
        >
          {t("label.spotify-playlist")}
        </a>
      </td>
    );
  }

  return srcTd;
}

export default SourceTd;
