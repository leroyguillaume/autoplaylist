import React, { useContext } from "react";
import { Role, synchronizationIsRunning, type Synchronization } from "./api";
import { AppContext } from ".";
import { Button } from "react-bootstrap";
import { faArrowsRotate } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";

interface Props {
  sync: Synchronization;
  onClick: () => void;
}

function SynchronizeButton(props: Props): JSX.Element {
  const state = useContext(AppContext);

  let syncBtn = <></>;
  if (state.auth?.role === Role.Admin) {
    const disabled = synchronizationIsRunning(props.sync);
    syncBtn = (
      <Button
        variant="secondary"
        disabled={disabled}
        className="me-1 mb-1 mb-lg-0"
        onClick={props.onClick}
      >
        <FontAwesomeIcon icon={faArrowsRotate} />
      </Button>
    );
  }

  return syncBtn;
}

export default SynchronizeButton;
