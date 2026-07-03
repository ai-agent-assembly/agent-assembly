//! BPF ring-buffer consumer: reads events from kernel-space to userspace.
//!
//! All three eBPF sub-tasks (AAASM-37, 38, 39) emit events through a shared
//! BPF ring buffer map.  `RingBufReader` multiplexes the three event types
//! and dispatches them to registered callbacks.

use std::mem;

use aa_ebpf_common::{
    exec::{ExecEvent, ProcessExitEvent},
    file::FileIoEventRaw,
    tls::TlsCaptureEvent,
};
use aya::{
    maps::{MapData, RingBuf},
    Ebpf,
};
use tokio::io::unix::AsyncFd;

use crate::error::EbpfError;

/// Dispatched event variants read from the shared BPF ring buffer.
#[derive(Debug)]
pub enum EbpfEvent {
    /// TLS plaintext capture (AAASM-37).
    Tls(Box<TlsCaptureEvent>),
    /// File I/O operation (AAASM-38).
    File(Box<FileIoEventRaw>),
    /// Process exec (AAASM-39).
    Exec(Box<ExecEvent>),
    /// Process exit (AAASM-39).
    Exit(Box<ProcessExitEvent>),
}

/// Async consumer that reads [`EbpfEvent`]s from the BPF ring buffer.
///
/// Create via [`RingBufReader::new`], then poll with [`RingBufReader::next`]
/// inside a Tokio task.
///
/// The reader keeps the `Ebpf` handle alive so that all loaded programs and
/// maps remain in the kernel for the lifetime of the reader.
pub struct RingBufReader {
    /// Keeps loaded BPF programs alive; dropping this detaches all probes.
    _bpf: Ebpf,
    /// Async-ready wrapper around the `EVENTS` ring buffer map.
    async_fd: AsyncFd<RingBuf<MapData>>,
}

impl RingBufReader {
    /// Construct a `RingBufReader` from a loaded `Ebpf` handle.
    ///
    /// Takes ownership of `bpf`, extracts the `EVENTS` ring buffer map, and
    /// wraps it in a `tokio::io::unix::AsyncFd` for non-blocking polling.
    ///
    /// # Errors
    ///
    /// Returns [`EbpfError::MapNotFound`] if the `EVENTS` map is absent.
    /// Returns [`EbpfError::Map`] if the map cannot be interpreted as a ring buffer.
    /// Returns [`EbpfError::Io`] if the `AsyncFd` registration fails.
    pub fn new(mut bpf: Ebpf) -> Result<Self, EbpfError> {
        let map = bpf
            .take_map("EVENTS")
            .ok_or_else(|| EbpfError::MapNotFound { name: "EVENTS".into() })?;
        let ring_buf = RingBuf::try_from(map)?;
        let async_fd = AsyncFd::new(ring_buf)?;
        Ok(Self { _bpf: bpf, async_fd })
    }

    /// Read the next event from the ring buffer (async).
    ///
    /// Waits until the kernel signals that data is available, then drains one
    /// entry, copies its bytes, and returns the parsed event.
    ///
    /// Returns `None` when the ring buffer has been closed (loader shut down).
    ///
    /// # Errors
    ///
    /// Returns [`EbpfError::Io`] if the async wait fails.
    /// Returns [`EbpfError::EventSize`] if the raw bytes cannot be
    /// interpreted as a known event type.
    pub async fn next(&mut self) -> Result<Option<EbpfEvent>, EbpfError> {
        loop {
            let mut guard = self.async_fd.readable_mut().await?;
            let rb = guard.get_inner_mut();
            // Copy the raw bytes out before releasing the borrow on `guard`.
            let raw: Option<Vec<u8>> = rb.next().map(|item| item.to_vec());
            guard.clear_ready();
            if let Some(bytes) = raw {
                return Ok(Some(parse_event(&bytes)?));
            }
            // Ring buffer was readable but contained no complete record yet —
            // loop and wait for the next readability notification.
        }
    }
}

/// Discriminate a raw byte slice by size and copy it into an owned event.
///
/// Sizes (from `#[repr(C)]` layout):
/// - [`TlsCaptureEvent`]: 8 + 4 + 4 + 4 + 4 + 1 + 7 + 4096 = 4128 bytes
/// - [`FileIoEventRaw`]:  see struct for exact layout
/// - [`ExecEvent`]:  8 + 4 + 4 + 4 + 4 + 256 + 512 = 792 bytes
fn parse_event(bytes: &[u8]) -> Result<EbpfEvent, EbpfError> {
    match bytes.len() {
        n if n == mem::size_of::<TlsCaptureEvent>() => Ok(EbpfEvent::Tls(Box::new(bytes_to::<TlsCaptureEvent>(bytes)))),
        n if n == mem::size_of::<FileIoEventRaw>() => Ok(EbpfEvent::File(Box::new(bytes_to::<FileIoEventRaw>(bytes)))),
        n if n == mem::size_of::<ExecEvent>() => Ok(EbpfEvent::Exec(Box::new(bytes_to::<ExecEvent>(bytes)))),
        n if n == mem::size_of::<ProcessExitEvent>() => {
            Ok(EbpfEvent::Exit(Box::new(bytes_to::<ProcessExitEvent>(bytes))))
        }
        got => Err(EbpfError::EventSize {
            expected: mem::size_of::<TlsCaptureEvent>(),
            got,
        }),
    }
}

/// Copy `bytes` into a new instance of `T` via a raw pointer copy.
///
/// # Safety
///
/// `T` must be `#[repr(C)]` and `Copy`.  The caller must guarantee that
/// `bytes.len() == size_of::<T>()` (enforced by [`parse_event`]).
fn bytes_to<T: Copy>(bytes: &[u8]) -> T {
    assert_eq!(bytes.len(), mem::size_of::<T>());
    // SAFETY: T is #[repr(C)] and Copy; size equality is checked above.
    let mut value = mem::MaybeUninit::<T>::uninit();
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), value.as_mut_ptr().cast::<u8>(), bytes.len());
        value.assume_init()
    }
}
