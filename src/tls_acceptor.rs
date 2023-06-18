use std::{
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use anyhow::Result;
use futures::Stream;
use hyper::server::{
    accept::Accept,
    conn::{AddrIncoming, AddrStream},
};
use log::{error, warn};
use rustls::{server::Acceptor, ServerConfig};
use tokio::sync::{mpsc, watch};
use tokio_rustls::{server::TlsStream, LazyConfigAcceptor};
use tokio_stream::{wrappers::ReceiverStream, StreamExt};

pub struct TlsIncoming {
    incoming: StreamWrapper,
    tls_config: watch::Receiver<Option<Arc<ServerConfig>>>,
}

struct StreamWrapper(AddrIncoming);

impl Stream for StreamWrapper {
    type Item = Result<AddrStream, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.0).poll_accept(cx)
    }
}

impl TlsIncoming {
    pub fn new(
        listen: SocketAddr,
        nodelay: bool,
        keepalive: Option<Duration>,
        tls_config: watch::Receiver<Option<Arc<ServerConfig>>>,
    ) -> Result<Self> {
        let mut incoming = AddrIncoming::bind(&listen)?;
        incoming.set_nodelay(nodelay);
        incoming.set_keepalive(keepalive);

        Ok(Self {
            incoming: StreamWrapper(incoming),
            tls_config,
        })
    }

    pub fn start(mut self) -> impl Stream<Item = Result<TlsStream<AddrStream>, std::io::Error>> {
        let (sender, receiver) = mpsc::channel::<Result<TlsStream<AddrStream>, std::io::Error>>(10);
        tokio::spawn(async move {
            loop {
                let client = match self.incoming.next().await {
                    Some(Ok(x)) => x,
                    Some(Err(e)) => {
                        error!("error during accepting TCP client: {e}");
                        continue;
                    }
                    None => break,
                };
                let Some(server_config) = self.tls_config.borrow().clone() else {
                    warn!("inbound TLS connection dropped (no certificates loaded, but were configured)");
                    continue
                };

                let lazy = LazyConfigAcceptor::new(Acceptor::default(), client);
                let sender = sender.clone();
                tokio::spawn(async move {
                    let accepted = match lazy.await {
                        Ok(x) => x,
                        Err(e) => {
                            error!("error during TLS init: {e}");
                            return;
                        }
                    };
                    let tls_stream = accepted.into_stream(server_config).await;
                    if sender.send(tls_stream).await.is_err() {
                        error!("TLS acceptor hung");
                    }
                });
            }
        });
        ReceiverStream::new(receiver)
    }
}
