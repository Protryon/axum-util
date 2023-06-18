use std::{
    fmt,
    pin::Pin,
    task::{Context, Poll},
};

use axum::body::BoxBody;
use futures::Future;
use http::{HeaderValue, Method, Request, Response, StatusCode};
use http_body::{Body, Empty};
use tower_layer::Layer;
use tower_service::Service;

#[derive(Clone)]
pub struct CorsLayer;

impl<S> Layer<S> for CorsLayer {
    type Service = Cors<S>;

    fn layer(&self, service: S) -> Self::Service {
        Cors::new(service)
    }
}

#[derive(Clone)]
pub struct Cors<S> {
    inner: S,
}

impl<S> Cors<S> {
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

#[pin_project::pin_project]
pub struct CorsFuture<S, ReqBody, ResBody>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    S::Error: fmt::Display + 'static,
{
    #[pin]
    inner: S::Future,
}

impl<S, ReqBody, ResBody> Future for CorsFuture<S, ReqBody, ResBody>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    S::Error: fmt::Display + 'static,
{
    type Output = <S::Future as Future>::Output;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        match this.inner.poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(mut response)) => {
                response
                    .headers_mut()
                    .insert("access-control-allow-origin", HeaderValue::from_static("*"));
                response.headers_mut().insert(
                    "access-control-allow-methods",
                    HeaderValue::from_static("POST, GET, OPTIONS, PATCH, DELETE"),
                );
                response.headers_mut().insert(
                    "access-control-allow-headers",
                    HeaderValue::from_static("content-type"),
                );
                Poll::Ready(Ok(response))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }
}

impl<S, ReqBody> Service<Request<ReqBody>> for Cors<S>
where
    S: Service<Request<ReqBody>, Response = Response<BoxBody>>,
    ReqBody: Body + 'static,
    S: 'static,
    S::Error: fmt::Display + 'static,
    S::Future: Send,
{
    type Response = Response<BoxBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>; //CorsFuture<S, ReqBody, ResBody>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        if req.method() == Method::OPTIONS && req.uri().path().starts_with("/api/v1/") {
            return Box::pin(async move {
                let mut response: Response<BoxBody> =
                    Response::new(axum::body::boxed(Empty::new()));
                *response.status_mut() = StatusCode::OK;
                response
                    .headers_mut()
                    .insert("access-control-allow-origin", HeaderValue::from_static("*"));
                response.headers_mut().insert(
                    "access-control-allow-methods",
                    HeaderValue::from_static("POST, GET, OPTIONS, PATCH, DELETE"),
                );
                response.headers_mut().insert(
                    "access-control-allow-headers",
                    HeaderValue::from_static("*"),
                );
                response
                    .headers_mut()
                    .insert("access-control-max-age", HeaderValue::from_static("86400"));
                Ok(response)
            });
        }
        let future = self.inner.call(req);

        Box::pin(CorsFuture::<S, ReqBody, BoxBody> { inner: future })
    }
}
