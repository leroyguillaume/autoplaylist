use autoplaylist_common::api::JwtClaims;
use jsonwebtoken::{DecodingKey, Validation};
use tracing::debug;
use uuid::Uuid;

// JwtDecoder

#[cfg_attr(test, mockall::automock)]
pub trait JwtDecoder: Send + Sync {
    fn decode(&self, jwt: &str) -> jsonwebtoken::errors::Result<Uuid>;
}

// DefaultJwtDecoder

pub struct DefaultJwtDecoder;

impl JwtDecoder for DefaultJwtDecoder {
    fn decode(&self, jwt: &str) -> jsonwebtoken::errors::Result<Uuid> {
        debug!("decoding JWT headers");
        let headers = jsonwebtoken::decode_header(jwt)?;
        let mut validation = Validation::new(headers.alg);
        validation.insecure_disable_signature_validation();
        let key = DecodingKey::from_secret(&[]);
        let data = jsonwebtoken::decode::<JwtClaims>(jwt, &key, &validation)?;
        Ok(data.claims.sub)
    }
}

// Tests

#[cfg(test)]
mod test {
    use super::*;

    use autoplaylist_common::model::Role;
    use chrono::Utc;
    use jsonwebtoken::{EncodingKey, Header};

    mod default_jwt_decoder {
        use super::*;

        // Mods

        mod decode {
            use super::*;

            #[test]
            fn sub() {
                let encoding_key = EncodingKey::from_secret("changeit".as_bytes());
                let claims = JwtClaims {
                    exp: Utc::now().timestamp(),
                    role: Role::User,
                    sub: Uuid::new_v4(),
                };
                let jwt = jsonwebtoken::encode(&Header::default(), &claims, &encoding_key)
                    .expect("failed to encode JWT");
                let decoder = DefaultJwtDecoder;
                let id = decoder.decode(&jwt).expect("failed to decode JWT");
                assert_eq!(id, claims.sub);
            }
        }
    }
}
