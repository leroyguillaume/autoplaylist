import React from "react";
import {
  predicateIsYearIs,
  type Predicate,
  predicateIsArtistsAre,
  predicateIsArtistsAreExactly,
  predicateIsYearIsBetween,
  predicateIsAnd,
  predicateIsOr,
} from "./api";
import {
  Button,
  Dropdown,
  Form,
  FormControl,
  InputGroup,
} from "react-bootstrap";
import { t } from "i18next";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faPlus, faTrash } from "@fortawesome/free-solid-svg-icons";

enum Kind {
  ArtistsAre = "artists-are",
  ArtistsAreExactly = "artists-are-exactly",
  YearIs = "year-is",
  YearIsBetween = "year-is-between",
}

enum Operator {
  And = "and",
  Or = "or",
}

interface Props {
  left?: boolean;
  lvl?: number;
  predicate: Predicate;
  onChange: (predicate: Predicate) => void;
}

function PredicateControl(props: Props): JSX.Element {
  const predicate = props.predicate;

  const updateKind = (kind: Kind): void => {
    switch (kind) {
      case Kind.ArtistsAre:
        props.onChange({ artistsAre: [] });
        break;
      case Kind.ArtistsAreExactly:
        props.onChange({ artistsAreExactly: [] });
        break;
      case Kind.YearIs:
        props.onChange({ yearIs: 1993 });
        break;
      case Kind.YearIsBetween:
        props.onChange({ yearIsBetween: [1990, 1999] });
        break;
    }
  };

  const buildArtistsControl = (
    kind: Kind,
    artists: string[],
    onChange: (artists: string[]) => void,
  ): JSX.Element => {
    return (
      <InputGroup className="mb-2">
        {buildKindSelect(kind)}
        <FormControl
          type="string"
          defaultValue={artists.join(", ")}
          onChange={(evt) => {
            onChange(evt.target.value.split(","));
          }}
          placeholder={t("placeholder.artists")}
          required
        />
        {addBtn}
        <Form.Control.Feedback type="invalid">
          {t("validation.artists")}
        </Form.Control.Feedback>
      </InputGroup>
    );
  };

  const buildKindSelect = (kind: Kind): JSX.Element => {
    return (
      <Form.Select
        defaultValue={kind}
        onChange={(evt) => {
          updateKind(evt.target.value as Kind);
        }}
      >
        <option value={Kind.ArtistsAre}>{t("predicate.artists-are")}</option>
        <option value={Kind.ArtistsAreExactly}>
          {t("predicate.artists-are-exactly")}
        </option>
        <option value={Kind.YearIs}>{t("predicate.year-is")}</option>
        <option value={Kind.YearIsBetween}>
          {t("predicate.year-is-between")}
        </option>
      </Form.Select>
    );
  };

  const buildOperatorControls = (
    predicates: [Predicate, Predicate],
    op: Operator,
    onChange: (predicates: [Predicate, Predicate]) => void,
  ): JSX.Element => {
    const padding = 20 * (props.lvl ?? 0);
    return (
      <div
        className="operator"
        style={{ paddingLeft: padding, paddingRight: padding }}
      >
        <PredicateControl
          predicate={predicates[0]}
          onChange={(newPredicate) => {
            onChange([predicates[0], newPredicate]);
          }}
          left={true}
          lvl={(props.lvl ?? 0) + 1}
        />
        <InputGroup className="mb-2">
          <Form.Select
            defaultValue={op}
            onChange={(evt) => {
              updateKind(evt.target.value as Kind);
            }}
          >
            <option value={Operator.And}>{t("predicate.and")}</option>
            <option value={Operator.Or}>{t("predicate.or")}</option>
          </Form.Select>
          <Button
            variant="danger"
            onClick={() => {
              props.onChange(predicates[0]);
            }}
          >
            <FontAwesomeIcon icon={faTrash} />
          </Button>
        </InputGroup>
        <PredicateControl
          predicate={predicates[1]}
          onChange={(newPredicate) => {
            onChange([predicates[0], newPredicate]);
          }}
          lvl={(props.lvl ?? 0) + 1}
        />
      </div>
    );
  };

  let addBtn = <></>;
  if (!(props.left ?? false)) {
    addBtn = (
      <Dropdown>
        <Dropdown.Toggle variant="secondary">
          <FontAwesomeIcon icon={faPlus} />
        </Dropdown.Toggle>

        <Dropdown.Menu>
          <Dropdown.Item
            onClick={() => {
              props.onChange({ and: [predicate, { artistsAre: [] }] });
            }}
          >
            {t("predicate.and")}
          </Dropdown.Item>
          <Dropdown.Item
            onClick={() => {
              props.onChange({ or: [predicate, { artistsAre: [] }] });
            }}
          >
            {t("predicate.or")}
          </Dropdown.Item>
        </Dropdown.Menu>
      </Dropdown>
    );
  }

  let control = <></>;
  if (predicateIsAnd(predicate)) {
    control = buildOperatorControls(predicate.and, Operator.And, (and) => {
      props.onChange({ and });
    });
  } else if (predicateIsArtistsAre(predicate)) {
    control = buildArtistsControl(
      Kind.ArtistsAre,
      predicate.artistsAre,
      (artistsAre) => {
        props.onChange({ artistsAre });
      },
    );
  } else if (predicateIsArtistsAreExactly(predicate)) {
    control = buildArtistsControl(
      Kind.ArtistsAreExactly,
      predicate.artistsAreExactly,
      (artistsAreExactly) => {
        props.onChange({ artistsAreExactly });
      },
    );
  } else if (predicateIsOr(predicate)) {
    control = buildOperatorControls(predicate.or, Operator.Or, (or) => {
      props.onChange({ or });
    });
  } else if (predicateIsYearIs(predicate)) {
    control = (
      <InputGroup className="mb-2">
        {buildKindSelect(Kind.YearIs)}
        <FormControl
          type="number"
          defaultValue={predicate.yearIs}
          onChange={(evt) => {
            props.onChange({ yearIs: Number(evt.target.value) });
          }}
        />
        {addBtn}
      </InputGroup>
    );
  } else if (predicateIsYearIsBetween(predicate)) {
    control = (
      <InputGroup className="mb-2">
        {buildKindSelect(Kind.YearIsBetween)}
        <FormControl
          type="number"
          defaultValue={predicate.yearIsBetween[0]}
          onChange={(evt) => {
            props.onChange({
              yearIsBetween: [
                Number(evt.target.value),
                predicate.yearIsBetween[1],
              ],
            });
          }}
        />
        <InputGroup.Text>{t("conjunction.and")}</InputGroup.Text>
        <FormControl
          type="number"
          defaultValue={predicate.yearIsBetween[1]}
          onChange={(evt) => {
            props.onChange({
              yearIsBetween: [
                predicate.yearIsBetween[0],
                Number(evt.target.value),
              ],
            });
          }}
        />
        {addBtn}
      </InputGroup>
    );
  }
  return control;
}

export default PredicateControl;
