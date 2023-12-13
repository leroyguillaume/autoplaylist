import React from "react";
import { type Source } from "./api";
import { PATH_ADMIN, PATH_USR } from ".";
import { LinkContainer } from "react-router-bootstrap";
import { useLocation } from "react-router";

interface Props {
  src: Source;
}

function OwnerTd(props: Props): JSX.Element {
  const loc = useLocation();

  return (
    <td>
      <LinkContainer
        to={`${PATH_ADMIN}${PATH_USR}/${props.src.owner.id}`}
        state={{ history: [...(loc.state?.history ?? []), loc.pathname] }}
      >
        <a>{props.src.owner.creds.spotify?.email ?? ""}</a>
      </LinkContainer>
    </td>
  );
}

export default OwnerTd;
