use std::collections::HashMap;
use std::net::SocketAddr;
use std::str;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use axum::error_handling::HandleErrorLayer;
use axum::extract::{Path, Query, State, TypedHeader};
use axum::headers::authorization::{Authorization, Bearer, Credentials};
use axum::headers::HeaderValue;
use axum::http::{Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

pub struct AcAuth {
  token: String,
}

impl Credentials for AcAuth {
  const SCHEME: &'static str = "AcAuth";

  fn decode(value: &HeaderValue) -> Option<Self> {
    debug_assert!(
      value.as_bytes().starts_with(b"AcAuth "),
      "HeaderValue to decode should start with \"AcAuth ..\", received = {:?}",
      value,
    );

    let bytes = &value.as_bytes()["AcAuth ".len()..];
    let non_space_pos = bytes.iter().position(|b| *b != b' ')?;
    let bytes = &bytes[non_space_pos..];
    let bytes = str::from_utf8(bytes);
    match bytes {
      Ok(v) => Some(AcAuth { token: v.to_string() }),
      Err(_) => None,
    }
  }

  fn encode(&self) -> HeaderValue {
    HeaderValue::from_str("base64 encoding is always a valid HeaderValue").unwrap()
  }
}

pub async fn auth<B>(
  TypedHeader(auth): TypedHeader<Authorization<AcAuth>>,
  request: Request<B>,
  next: Next<B>,
) -> Result<Response, StatusCode> {
  if token_is_valid(&auth.0.token) {
    let response = next.run(request).await;
    Ok(response)
  } else {
    Err(StatusCode::UNAUTHORIZED)
  }
}

fn token_is_valid(token: &str) -> bool {
  tracing::info!("got token {}...", token);
  true
}

#[allow(dead_code)]
fn app() -> Router {
    Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .layer(middleware::from_fn(auth))
}

#[cfg(test)]
mod middlewares_tests {

    use super::*;
    use axum::{
      body::Body,
      extract::connect_info::MockConnectInfo,
      http::{self, Request, StatusCode},
  };
  use serde_json::{json, Value};
  use std::net::{SocketAddr, TcpListener};
  use tower::Service; // for `call`
  use tower::ServiceExt; // for `oneshot` and `ready`

  #[tokio::test]
    async fn test_auth() {
      let app = app();
      let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
  }
