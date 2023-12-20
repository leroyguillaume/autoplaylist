use autoplaylist_common::{
    api::{
        CredentialsResponse, PlaylistResponse, SourceResponse, SpotifyCredentialsResponse,
        SynchronizationResponse, UserResponse,
    },
    model::{
        Credentials, Playlist, PlaylistSynchronization, Role, Source, SourceSynchronization,
        Synchronization, SynchronizationStep, User,
    },
};

// Converter

#[cfg_attr(test, mockall::automock)]
pub trait Converter: Send + Sync {
    fn convert_credentials(&self, creds: Credentials) -> CredentialsResponse;

    fn convert_playlist(&self, playlist: Playlist, auth_usr: &User) -> PlaylistResponse;

    fn convert_source(&self, src: Source, auth_usr: &User) -> SourceResponse;

    fn convert_playlist_synchronization(
        &self,
        sync: PlaylistSynchronization,
        auth_usr: &User,
    ) -> SynchronizationResponse;

    fn convert_source_synchronization(
        &self,
        sync: SourceSynchronization,
        auth_usr: &User,
    ) -> SynchronizationResponse;

    fn convert_user(&self, usr: User) -> UserResponse;
}

// DefaultConverter

pub struct DefaultConverter;

impl DefaultConverter {
    #[inline]
    fn convert_synchronization<STEP: SynchronizationStep>(
        sync: Synchronization<STEP>,
        auth_usr: &User,
    ) -> SynchronizationResponse {
        match sync {
            Synchronization::Aborted { end, state } => SynchronizationResponse::Aborted {
                end,
                start: state.start,
            },
            Synchronization::Failed {
                details,
                end,
                state,
            } => SynchronizationResponse::Failed {
                details: if auth_usr.role == Role::Admin {
                    Some(details)
                } else {
                    None
                },
                end,
                start: state.start,
            },
            Synchronization::Pending => SynchronizationResponse::Pending,
            Synchronization::Running(start) => SynchronizationResponse::Running(start),
            Synchronization::Succeeded { end, start } => {
                SynchronizationResponse::Succeeded { end, start }
            }
        }
    }
}

impl Converter for DefaultConverter {
    fn convert_credentials(&self, creds: Credentials) -> CredentialsResponse {
        CredentialsResponse {
            spotify: creds.spotify.map(|creds| SpotifyCredentialsResponse {
                email: creds.email,
                id: creds.id,
            }),
        }
    }

    fn convert_playlist(&self, playlist: Playlist, auth_usr: &User) -> PlaylistResponse {
        PlaylistResponse {
            creation: playlist.creation,
            id: playlist.id,
            name: playlist.name,
            predicate: playlist.predicate,
            src: self.convert_source(playlist.src, auth_usr),
            sync: self.convert_playlist_synchronization(playlist.sync, auth_usr),
            tgt: playlist.tgt,
        }
    }

    fn convert_playlist_synchronization(
        &self,
        sync: PlaylistSynchronization,
        auth_usr: &User,
    ) -> SynchronizationResponse {
        Self::convert_synchronization(sync, auth_usr)
    }

    fn convert_source(&self, src: Source, auth_usr: &User) -> SourceResponse {
        SourceResponse {
            creation: src.creation,
            id: src.id,
            kind: src.kind,
            owner: self.convert_user(src.owner),
            sync: self.convert_source_synchronization(src.sync, auth_usr),
        }
    }

    fn convert_source_synchronization(
        &self,
        sync: SourceSynchronization,
        auth_usr: &User,
    ) -> SynchronizationResponse {
        Self::convert_synchronization(sync, auth_usr)
    }

    fn convert_user(&self, usr: User) -> UserResponse {
        UserResponse {
            creation: usr.creation,
            creds: self.convert_credentials(usr.creds),
            id: usr.id,
            role: usr.role,
        }
    }
}

// Tests

#[cfg(test)]
mod test {
    use autoplaylist_common::model::{
        Credentials, PlaylistSynchronizationState, PlaylistSynchronizationStep, Predicate, Role,
        SourceKind, SourceSynchronizationState, SourceSynchronizationStep, SpotifyCredentials,
        SpotifySourceKind, SpotifyToken, Target, User,
    };
    use chrono::Utc;
    use uuid::Uuid;

    use super::*;

    // Mods

    mod default_converter {
        use super::*;

        // Macros

        macro_rules! convert_sync {
            ($ident:ident, $sync:ident, $state:ident, $step:ident) => {
                mod $ident {
                    use super::*;

                    // Tests

                    #[test]
                    fn aborted() {
                        let end = Utc::now();
                        let usr = User {
                            creation: Utc::now(),
                            creds: Default::default(),
                            id: Uuid::new_v4(),
                            role: Role::Admin,
                        };
                        let state = $state {
                            start: Utc::now(),
                            step: $step::Finished,
                        };
                        let sync = $sync::Aborted { end, state };
                        let expected = SynchronizationResponse::Aborted {
                            end,
                            start: state.start,
                        };
                        let resp = DefaultConverter.$ident(sync, &usr);
                        assert_eq!(resp, expected);
                    }

                    #[test]
                    fn failed_when_admin() {
                        let end = Utc::now();
                        let details = "details";
                        let usr = User {
                            creation: Utc::now(),
                            creds: Default::default(),
                            id: Uuid::new_v4(),
                            role: Role::Admin,
                        };
                        let state = $state {
                            start: Utc::now(),
                            step: $step::Finished,
                        };
                        let sync = $sync::Failed {
                            details: details.into(),
                            end,
                            state,
                        };
                        let expected = SynchronizationResponse::Failed {
                            details: Some(details.into()),
                            end,
                            start: state.start,
                        };
                        let resp = DefaultConverter.$ident(sync, &usr);
                        assert_eq!(resp, expected);
                    }

                    #[test]
                    fn failed_when_user() {
                        let end = Utc::now();
                        let details = "details";
                        let usr = User {
                            creation: Utc::now(),
                            creds: Default::default(),
                            id: Uuid::new_v4(),
                            role: Role::User,
                        };
                        let state = $state {
                            start: Utc::now(),
                            step: $step::Finished,
                        };
                        let sync = $sync::Failed {
                            details: details.into(),
                            end,
                            state,
                        };
                        let expected = SynchronizationResponse::Failed {
                            details: None,
                            end,
                            start: state.start,
                        };
                        let resp = DefaultConverter.$ident(sync, &usr);
                        assert_eq!(resp, expected);
                    }

                    #[test]
                    fn pending() {
                        let usr = User {
                            creation: Utc::now(),
                            creds: Default::default(),
                            id: Uuid::new_v4(),
                            role: Role::Admin,
                        };
                        let sync = $sync::Pending;
                        let expected = SynchronizationResponse::Pending;
                        let resp = DefaultConverter.$ident(sync, &usr);
                        assert_eq!(resp, expected);
                    }

                    #[test]
                    fn running() {
                        let start = Utc::now();
                        let usr = User {
                            creation: Utc::now(),
                            creds: Default::default(),
                            id: Uuid::new_v4(),
                            role: Role::Admin,
                        };
                        let sync = $sync::Running(start);
                        let expected = SynchronizationResponse::Running(start);
                        let resp = DefaultConverter.$ident(sync, &usr);
                        assert_eq!(resp, expected);
                    }

                    #[test]
                    fn succeeded() {
                        let start = Utc::now();
                        let end = Utc::now();
                        let usr = User {
                            creation: Utc::now(),
                            creds: Default::default(),
                            id: Uuid::new_v4(),
                            role: Role::Admin,
                        };
                        let sync = $sync::Succeeded { end, start };
                        let expected = SynchronizationResponse::Succeeded { end, start };
                        let resp = DefaultConverter.$ident(sync, &usr);
                        assert_eq!(resp, expected);
                    }
                }
            };
        }

        // Mods

        mod convert_credentials {
            use super::*;

            #[test]
            fn response() {
                let spotify_creds = SpotifyCredentials {
                    email: "email".to_string(),
                    id: "id".to_string(),
                    token: SpotifyToken {
                        access: "access".to_string(),
                        expiration: Utc::now(),
                        refresh: "refresh".to_string(),
                    },
                };
                let creds = Credentials {
                    spotify: Some(spotify_creds.clone()),
                };
                let expected = CredentialsResponse {
                    spotify: Some(SpotifyCredentialsResponse {
                        email: spotify_creds.email.clone(),
                        id: spotify_creds.id.clone(),
                    }),
                };
                let resp = DefaultConverter.convert_credentials(creds);
                assert_eq!(resp, expected);
            }
        }

        mod convert_playlist {
            use super::*;

            #[test]
            fn response() {
                let usr = User {
                    creation: Utc::now(),
                    creds: Default::default(),
                    id: Uuid::new_v4(),
                    role: Role::Admin,
                };
                let playlist = Playlist {
                    creation: Utc::now(),
                    id: Uuid::new_v4(),
                    name: "name".to_string(),
                    predicate: Predicate::YearIs(1993),
                    src: Source {
                        creation: Utc::now(),
                        id: Uuid::new_v4(),
                        kind: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                        owner: usr.clone(),
                        sync: Synchronization::Pending,
                    },
                    sync: Synchronization::Pending,
                    tgt: Target::Spotify("id".into()),
                };
                let expected = PlaylistResponse {
                    creation: playlist.creation,
                    id: playlist.id,
                    name: playlist.name.clone(),
                    predicate: playlist.predicate.clone(),
                    src: DefaultConverter.convert_source(playlist.src.clone(), &usr),
                    sync: DefaultConverter
                        .convert_playlist_synchronization(playlist.sync.clone(), &usr),
                    tgt: playlist.tgt.clone(),
                };
                let resp = DefaultConverter.convert_playlist(playlist, &usr);
                assert_eq!(resp, expected);
            }
        }

        convert_sync!(
            convert_playlist_synchronization,
            PlaylistSynchronization,
            PlaylistSynchronizationState,
            PlaylistSynchronizationStep
        );

        mod convert_source {
            use super::*;

            #[test]
            fn response() {
                let usr = User {
                    creation: Utc::now(),
                    creds: Default::default(),
                    id: Uuid::new_v4(),
                    role: Role::Admin,
                };
                let src = Source {
                    creation: Utc::now(),
                    id: Uuid::new_v4(),
                    kind: SourceKind::Spotify(SpotifySourceKind::SavedTracks),
                    owner: usr.clone(),
                    sync: Synchronization::Pending,
                };
                let expected = SourceResponse {
                    creation: src.creation,
                    id: src.id,
                    kind: src.kind.clone(),
                    owner: DefaultConverter.convert_user(usr.clone()),
                    sync: DefaultConverter.convert_source_synchronization(src.sync.clone(), &usr),
                };
                let resp = DefaultConverter.convert_source(src, &usr);
                assert_eq!(resp, expected);
            }
        }

        convert_sync!(
            convert_source_synchronization,
            SourceSynchronization,
            SourceSynchronizationState,
            SourceSynchronizationStep
        );

        mod convert_user {
            use super::*;

            #[test]
            fn response() {
                let usr = User {
                    creation: Utc::now(),
                    creds: Default::default(),
                    id: Uuid::new_v4(),
                    role: Role::Admin,
                };
                let expected = UserResponse {
                    creation: usr.creation,
                    creds: DefaultConverter.convert_credentials(usr.creds.clone()),
                    id: usr.id,
                    role: usr.role,
                };
                let resp = DefaultConverter.convert_user(usr);
                assert_eq!(resp, expected);
            }
        }
    }
}
