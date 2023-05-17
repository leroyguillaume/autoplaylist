import { useContext } from "react";
import { Alert as BootstrapAlert, Container, Row } from "react-bootstrap";
import { Context, Error, Info } from "./ctx";

export default function Alert() {
  const ctx = useContext(Context);

  const infoAlert = createAlert(
    ctx.info,
    "success",
    (info) => {
      switch (info) {
        case Info.QueryCreated:
          return "Query successfully created! 🥳";
        default:
          return "It seems you find a bug! 😤";
      }
    },
    () => ctx.setInfo(null)
  );
  const errorAlert = createAlert(
    ctx.error,
    "danger",
    (err) => {
      switch (err) {
        case Error.QueryAlreadyExists:
          return "A similar query already exists! 🫣";
        case Error.Unauthorized:
          return "You're not authenticated, hacker! 😏";
        case Error.Unexpected:
          return "An unexpected error occurred, please retry later 😭";
        default:
          return "It seems you find a bug! 😤";
      }
    },
    () => ctx.setError(null)
  );

  return (
    <Container>
      <Row>
        {errorAlert}
        {infoAlert}
      </Row>
    </Container>
  );
}

function createAlert<T>(
  val: T | null,
  variant: string,
  toString: (val: T) => string,
  onClose: () => void
) {
  if (val === null) {
    return <></>;
  } else {
    return (
      <>
        <div className="col-12 text-center">
          <BootstrapAlert dismissible onClose={onClose} variant={variant}>
            {toString(val)}
          </BootstrapAlert>
        </div>
      </>
    );
  }
}
