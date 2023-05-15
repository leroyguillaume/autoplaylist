use serde::{Deserialize, Serialize};

// Structs - Requests

#[derive(Deserialize)]
pub struct AuthWithSpotifyRequest {
    pub code: String,
}

// Structs - Response

#[derive(Serialize)]
pub struct JwtResponse {
    pub jwt: String,
}
