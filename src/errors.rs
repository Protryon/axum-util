use std::fmt;

use axum::{
    response::{IntoResponse, Response},
    Json,
};
use http::{header::LOCATION, StatusCode};
use log::error;
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Serialize, Deserialize)]
pub struct ErrorBody {
    pub message: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RedirectMode {
    MovedPermanently,
    #[default]
    Found,
    SeeOther,
    TemporaryRedirect,
    PermanentRedirect,
}

impl RedirectMode {
    pub fn status_code(&self) -> StatusCode {
        match self {
            RedirectMode::MovedPermanently => StatusCode::MOVED_PERMANENTLY,
            RedirectMode::Found => StatusCode::FOUND,
            RedirectMode::SeeOther => StatusCode::SEE_OTHER,
            RedirectMode::TemporaryRedirect => StatusCode::TEMPORARY_REDIRECT,
            RedirectMode::PermanentRedirect => StatusCode::PERMANENT_REDIRECT,
        }
    }
}

#[derive(Debug)]
pub enum ApiError {
    Redirect(RedirectMode, Url),
    NotModified,
    BadRequest(String),
    Unauthorized(String),
    Forbidden(String),
    NotFound,
    Response(Response),
    Other(anyhow::Error),
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <Self as fmt::Debug>::fmt(self, f)
    }
}

impl<E: std::error::Error + Send + Sync + 'static> From<E> for ApiError {
    fn from(error: E) -> Self {
        Self::Other(anyhow::Error::from(error))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            ApiError::Redirect(mode, destination) => {
                (mode.status_code(), [(LOCATION, destination.to_string())]).into_response()
            }
            ApiError::NotModified => StatusCode::NOT_MODIFIED.into_response(),
            ApiError::BadRequest(message) => {
                (StatusCode::BAD_REQUEST, Json(ErrorBody { message })).into_response()
            }
            ApiError::Unauthorized(message) => {
                (StatusCode::UNAUTHORIZED, Json(ErrorBody { message })).into_response()
            }
            ApiError::Forbidden(message) => {
                (StatusCode::FORBIDDEN, Json(ErrorBody { message })).into_response()
            }
            ApiError::NotFound => (
                StatusCode::NOT_FOUND,
                Json(ErrorBody {
                    message: "not found".to_string(),
                }),
            )
                .into_response(),
            ApiError::Response(response) => response,
            ApiError::Other(e) => {
                error!("internal error: {:#}", e);
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
