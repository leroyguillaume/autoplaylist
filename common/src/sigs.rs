use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::signal::unix::{signal, Signal, SignalKind};
use tracing::trace;

// TerminationSignalListener

pub struct TerminationSignalListener {
    int: Signal,
    term: Signal,
}

impl TerminationSignalListener {
    pub fn init() -> io::Result<Self> {
        Ok(Self {
            int: Self::signal("SIGINT", SignalKind::interrupt())?,
            term: Self::signal("SIGTERM", SignalKind::terminate())?,
        })
    }

    #[inline]
    fn signal(name: &str, kind: SignalKind) -> io::Result<Signal> {
        trace!("creating signal `{name}`");
        signal(kind)
    }
}

impl Future for TerminationSignalListener {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.int.poll_recv(cx).is_ready() {
            trace!("SIGINT received");
            Poll::Ready(())
        } else if this.term.poll_recv(cx).is_ready() {
            trace!("SIGTERM received");
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}
