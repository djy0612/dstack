use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{anyhow, bail, Context as _, Result};
use fs_err as fs;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::tokio::TokioIo;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::version::{TLS12, TLS13};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::{rustls, server::TlsStream, TlsAcceptor};
use tracing::{debug, info};

use crate::config::{CryptoProvider, ProxyConfig, TlsVersion};
use crate::main_service::Proxy;

use super::io_bridge::bridge;
use super::tls_passthough::connect_multiple_hosts;

#[pin_project::pin_project]
struct IgnoreUnexpectedEofStream<S> {
    #[pin]
    stream: S,
}

impl<S> IgnoreUnexpectedEofStream<S> {
    fn new(stream: S) -> Self {
        Self { stream }
    }
}

impl<S> AsyncRead for IgnoreUnexpectedEofStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.project().stream.poll_read(cx, buf) {
            Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof => Poll::Ready(Ok(())),
            output => output,
        }
    }
}

impl<S> AsyncWrite for IgnoreUnexpectedEofStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.project().stream.poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), io::Error>> {
        self.project().stream.poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), io::Error>> {
        self.project().stream.poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<std::result::Result<usize, io::Error>> {
        self.project().stream.poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }
}

pub(crate) fn create_acceptor(config: &ProxyConfig) -> Result<TlsAcceptor> {
    let cert_pem = fs::read(&config.cert_chain).context("failed to read certificate")?;
    let key_pem = fs::read(&config.cert_key).context("failed to read private key")?;
    let certs = CertificateDer::pem_slice_iter(cert_pem.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .context("failed to parse certificate")?;
    let key =
        PrivateKeyDer::from_pem_slice(key_pem.as_slice()).context("failed to parse private key")?;

    let provider = match config.tls_crypto_provider {
        CryptoProvider::AwsLcRs => rustls::crypto::aws_lc_rs::default_provider(),
        CryptoProvider::Ring => rustls::crypto::ring::default_provider(),
    };
    let supported_versions = config
        .tls_versions
        .iter()
        .map(|v| match v {
            TlsVersion::Tls12 => &TLS12,
            TlsVersion::Tls13 => &TLS13,
        })
        .collect::<Vec<_>>();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&supported_versions)
        .context("Failed to build TLS config")?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    let acceptor = TlsAcceptor::from(Arc::new(config));

    Ok(acceptor)
}

impl Proxy {
    /// Reload the TLS acceptor with fresh certificates
    pub fn reload_certificates(&self) -> Result<()> {
        info!("Reloading TLS certificates");
        let new_acceptor = create_acceptor(&self.config.proxy)?;

        // Replace the acceptor with the new one
        if let Ok(mut acceptor) = self.acceptor.write() {
            *acceptor = new_acceptor;
            info!("TLS certificates successfully reloaded");
        } else {
            bail!("Failed to acquire write lock for TLS acceptor");
        }

        Ok(())
    }

    pub(crate) async fn handle_health_check(
        &self,
        inbound: TcpStream,
        buffer: Vec<u8>,
        port: u16,
    ) -> Result<()> {
        if port != 80 {
            bail!("Only port 80 is supported for health checks");
        }
        let stream = self.tls_accept(inbound, buffer).await?;

        // Wrap the TLS stream with TokioIo to make it compatible with hyper 1.x
        let io = TokioIo::new(stream);

        let service = service_fn(|req: Request<Incoming>| async move {
            // Only respond to GET / requests
            if req.method() != hyper::Method::GET || req.uri().path() != "/" {
                return Ok::<_, anyhow::Error>(
                    Response::builder()
                        .status(StatusCode::METHOD_NOT_ALLOWED)
                        .body(String::new())
                        .unwrap(),
                );
            }
            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(String::new())
                .unwrap())
        });

        http1::Builder::new()
            .serve_connection(io, service)
            .await
            .context("Failed to serve HTTP connection")?;

        Ok(())
    }

    async fn tls_accept(
        &self,
        inbound: TcpStream,
        buffer: Vec<u8>,
    ) -> Result<TlsStream<MergedStream>> {
        let stream = MergedStream {
            buffer,
            buffer_cursor: 0,
            inbound,
        };
        let acceptor = self
            .acceptor
            .read()
            .expect("Failed to acquire read lock for TLS acceptor")
            .clone();
        let tls_stream = timeout(
            self.config.proxy.timeouts.handshake,
            acceptor.accept(stream),
        )
        .await
        .context("handshake timeout")?
        .context("failed to accept tls connection")?;
        Ok(tls_stream)
    }

    pub(crate) async fn proxy(
        &self,
        inbound: TcpStream,
        buffer: Vec<u8>,
        app_id: &str,
        port: u16,
    ) -> Result<()> {
        if app_id == "health" {
            return self.handle_health_check(inbound, buffer, port).await;
        }
        let addresses = self
            .lock()
            .select_top_n_hosts(app_id)
            .with_context(|| format!("app {app_id} not found"))?;
        debug!("selected top n hosts: {addresses:?}");
        let tls_stream = self.tls_accept(inbound, buffer).await?;
        let (outbound, _counter) = timeout(
            self.config.proxy.timeouts.connect,
            connect_multiple_hosts(addresses, port),
        )
        .await
        .map_err(|_| anyhow!("connecting timeout"))?
        .context("failed to connect to app")?;
        bridge(
            IgnoreUnexpectedEofStream::new(tls_stream),
            outbound,
            &self.config.proxy,
        )
        .await
        .context("bridge error")?;
        Ok(())
    }
}

#[pin_project::pin_project]
struct MergedStream {
    buffer: Vec<u8>,
    buffer_cursor: usize,
    #[pin]
    inbound: TcpStream,
}

impl AsyncRead for MergedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.project();
        let mut cursor = *this.buffer_cursor;
        if cursor < this.buffer.len() {
            let n = std::cmp::min(buf.remaining(), this.buffer.len() - cursor);
            buf.put_slice(&this.buffer[cursor..cursor + n]);
            cursor += n;
            if cursor == this.buffer.len() {
                cursor = 0;
                *this.buffer = vec![];
            }
            *this.buffer_cursor = cursor;
            return Poll::Ready(Ok(()));
        }
        this.inbound.poll_read(cx, buf)
    }
}
impl AsyncWrite for MergedStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::result::Result<usize, std::io::Error>> {
        self.project().inbound.poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), std::io::Error>> {
        self.project().inbound.poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), std::io::Error>> {
        self.project().inbound.poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<std::result::Result<usize, std::io::Error>> {
        self.project().inbound.poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inbound.is_write_vectored()
    }
}
