import { Container, Row } from "react-bootstrap";

export default function ErrorPage() {
  return (
    <>
      <Container className="v-offset">
        <Row>
          <div className="text-center">
            <h1>Oh no! It's a bug! 😭</h1>
          </div>
        </Row>
      </Container>
    </>
  );
}
