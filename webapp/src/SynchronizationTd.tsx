import React from "react";
import { t } from "i18next";
import {
  synchronizationIsRunning,
  type Synchronization,
  synchronizationIsAborted,
  synchronizationIsSucceeded,
  synchronizationIsFailed,
} from "./api";

interface Props {
  sync: Synchronization;
}

function SynchronizationTd(props: Props): JSX.Element {
  let syncTd = <td></td>;
  if (props.sync === "pending") {
    syncTd = <td className="sync-pending">{t("sync.pending")}</td>;
  } else if (synchronizationIsRunning(props.sync)) {
    const start = new Date(props.sync.running);
    syncTd = (
      <td className="sync-running">
        {t("sync.running")} {t("preposition.at")} {start.toLocaleTimeString()}
      </td>
    );
  } else if (synchronizationIsAborted(props.sync)) {
    const start = new Date(props.sync.aborted.start);
    syncTd = (
      <td className="sync-running">
        {t("sync.running")} {t("preposition.at")} {start.toLocaleTimeString()}
      </td>
    );
  } else if (synchronizationIsSucceeded(props.sync)) {
    const end = new Date(props.sync.succeeded.end);
    syncTd = (
      <td className="sync-succeeded">
        {t("sync.succeeded")} ({end.toLocaleDateString()} {t("preposition.at")}{" "}
        {end.toLocaleTimeString()})
      </td>
    );
  } else if (synchronizationIsFailed(props.sync)) {
    if (
      props.sync.failed.details !== undefined &&
      props.sync.failed.details !== null
    ) {
      syncTd = (
        <td className="sync-failed">
          {t("sync.failed")}
          {t("punctuation.colon")} {props.sync.failed.details}
        </td>
      );
    } else {
      syncTd = <td className="sync-failed">{t("sync.failed")}</td>;
    }
  }

  return syncTd;
}

export default SynchronizationTd;
