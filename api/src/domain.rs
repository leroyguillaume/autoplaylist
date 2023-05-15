use chrono::{DateTime, Utc};
use postgres_types::{FromSql, ToSql};
use securefmt::Debug;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// Enums

#[derive(Debug, Deserialize, FromSql, Serialize, ToSql)]
#[postgres(name = "role")]
#[serde(rename_all = "snake_case")]
pub enum Role {
    #[postgres(name = "admin")]
    Admin,
    #[postgres(name = "user")]
    User,
}

// Structs

#[derive(Debug)]
pub struct SpotifyAuth {
    pub email: String,
    #[sensitive]
    pub access_token: String,
    #[sensitive]
    pub refresh_token: Option<String>,
    pub user_id: Uuid,
}

#[derive(Debug)]
pub struct User {
    pub creation_date: DateTime<Utc>,
    pub id: Uuid,
    pub role: Role,
}
