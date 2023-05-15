import { useContext } from "react";
import { Alert as BootstrapAlert, Container, Row } from "react-bootstrap";
import { Context, Error } from "./ctx";

export default function Alert() {
  const ctx = useContext(Context);

  const closeError = () => {
    ctx.setError(null);
  };

  let errorAlert = <></>;
  if (ctx.error !== null) {
    let span;
    switch (ctx.error) {
      case Error.Unauthorized:
        span = <span>You're not authenticated, hacker!</span>;
        break;
      case Error.Unexpected:
        span = <span>An unexpected error occurred, please retry later 😭</span>;
        break;
      default:
        span = <span>It seems you find a bug! 😤</span>;
        break;
    }
    errorAlert = (
      <div className="col-12 text-center">
        <BootstrapAlert dismissible onClose={closeError} variant="danger">
          {span}
        </BootstrapAlert>
      </div>
    );
  }

  return (
    <Container>
      <Row>{errorAlert}</Row>
    </Container>
  );
}
