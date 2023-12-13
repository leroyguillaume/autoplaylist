import React from "react";
import { Button, Modal } from "react-bootstrap";
import { t } from "i18next";

interface Props {
  deleting: boolean;
  text: string;
  show: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}

function ConfirmationModal(props: Props): JSX.Element {
  let delBtn;
  if (props.deleting) {
    delBtn = (
      <Button variant="danger" disabled>
        {t("label.deleting")}
        {t("punctuation.ellipsis")}
      </Button>
    );
  } else {
    delBtn = (
      <Button variant="danger" onClick={props.onConfirm}>
        {t("label.delete")}
      </Button>
    );
  }

  return (
    <Modal show={props.show} onHide={props.onCancel}>
      <Modal.Header closeButton>
        <Modal.Title>{t("title.are-you-sure")}</Modal.Title>
      </Modal.Header>

      <Modal.Body>
        <p>{t(props.text)}</p>
      </Modal.Body>

      <Modal.Footer>
        <Button variant="secondary" onClick={props.onCancel}>
          {t("label.cancel")}
        </Button>
        {delBtn}
      </Modal.Footer>
    </Modal>
  );
}

export default ConfirmationModal;
