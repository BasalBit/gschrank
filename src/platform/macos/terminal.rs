//! Narrow no-echo terminal operations unavailable through the standard library.

use std::{
    io,
    sync::{
        Mutex,
        atomic::{AtomicI32, Ordering},
    },
};

use zeroize::Zeroizing;

const HANDLED_SIGNALS: [libc::c_int; 4] =
    [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT];

static TERMINAL_MUTEX: Mutex<()> = Mutex::new(());
static PENDING_SIGNAL: AtomicI32 = AtomicI32::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HiddenInputError {
    NotTerminal,
    IoFailure,
    Interrupted,
}

pub(crate) fn read_hidden_stdin(
    maximum_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, HiddenInputError> {
    read_hidden_fd(libc::STDIN_FILENO, maximum_bytes)
}

fn read_hidden_fd(
    descriptor: libc::c_int,
    maximum_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, HiddenInputError> {
    let _serialization = TERMINAL_MUTEX
        .lock()
        .map_err(|_| HiddenInputError::IoFailure)?;
    // SAFETY: `isatty` only inspects the supplied integer descriptor.
    if unsafe { libc::isatty(descriptor) } != 1 {
        return Err(HiddenInputError::NotTerminal);
    }

    PENDING_SIGNAL.store(0, Ordering::SeqCst);
    let mut signals = SignalGuard::install()?;
    let mut terminal = TerminalGuard::disable_echo(descriptor)?;
    let input = read_line_bytes(descriptor, maximum_bytes);
    let terminal_restore = terminal.restore();
    let signal_restore = signals.restore();
    let interrupted = PENDING_SIGNAL.swap(0, Ordering::SeqCst) != 0;
    match (input, terminal_restore, signal_restore, interrupted) {
        (Err(error), _, _, _) | (Ok(_), Err(error), _, _) | (Ok(_), Ok(()), Err(error), _) => {
            Err(error)
        }
        (Ok(_), Ok(()), Ok(()), true) => Err(HiddenInputError::Interrupted),
        (Ok(input), Ok(()), Ok(()), false) => Ok(input),
    }
}

fn read_line_bytes(
    descriptor: libc::c_int,
    maximum_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, HiddenInputError> {
    let retained_limit = maximum_bytes.saturating_add(1);
    let mut input = Zeroizing::new(Vec::new());
    input
        .try_reserve_exact(retained_limit)
        .map_err(|_| HiddenInputError::IoFailure)?;
    loop {
        if PENDING_SIGNAL.load(Ordering::SeqCst) != 0 {
            return Err(HiddenInputError::Interrupted);
        }

        let mut byte = 0_u8;
        // SAFETY: `byte` is writable for one byte and `descriptor` remains open
        // for the duration of this synchronous call.
        let read = unsafe { libc::read(descriptor, (&raw mut byte).cast(), 1) };
        if read == 1 {
            if byte == b'\n' {
                break;
            }
            if input.len() < retained_limit {
                input.push(byte);
            }
            continue;
        }
        if read == 0 {
            break;
        }

        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            if PENDING_SIGNAL.load(Ordering::SeqCst) != 0 {
                return Err(HiddenInputError::Interrupted);
            }
            continue;
        }
        return Err(HiddenInputError::IoFailure);
    }
    Ok(input)
}

struct TerminalGuard {
    descriptor: libc::c_int,
    original: libc::termios,
    active: bool,
}

impl TerminalGuard {
    fn disable_echo(descriptor: libc::c_int) -> Result<Self, HiddenInputError> {
        let mut original = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: `original` points to writable storage for one `termios` value.
        if unsafe { libc::tcgetattr(descriptor, original.as_mut_ptr()) } == -1 {
            return Err(HiddenInputError::IoFailure);
        }
        // SAFETY: successful `tcgetattr` initialized the complete value.
        let original = unsafe { original.assume_init() };
        let mut hidden = original;
        hidden.c_lflag &= !(libc::ECHO | libc::ECHONL);
        // SAFETY: both the descriptor and termios pointer are valid for this call.
        if unsafe { libc::tcsetattr(descriptor, libc::TCSAFLUSH, &raw const hidden) } == -1 {
            return Err(HiddenInputError::IoFailure);
        }
        Ok(Self {
            descriptor,
            original,
            active: true,
        })
    }

    fn restore(&mut self) -> Result<(), HiddenInputError> {
        if !self.active {
            return Ok(());
        }
        // Mark inactive only after a successful restore so `Drop` retries once
        // when an ordinary restore reports failure.
        // SAFETY: the descriptor and saved termios value remain valid.
        if unsafe { libc::tcsetattr(self.descriptor, libc::TCSANOW, &raw const self.original) }
            == -1
        {
            return Err(HiddenInputError::IoFailure);
        }
        self.active = false;
        Ok(())
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        if self.active {
            // SAFETY: best-effort restoration uses the still-open descriptor and
            // the termios value captured from that same descriptor.
            let _ = unsafe {
                libc::tcsetattr(self.descriptor, libc::TCSANOW, &raw const self.original)
            };
        }
    }
}

extern "C" fn record_signal(signal: libc::c_int) {
    PENDING_SIGNAL.store(signal, Ordering::SeqCst);
}

struct SignalGuard {
    originals: Vec<(libc::c_int, libc::sigaction)>,
}

impl SignalGuard {
    fn install() -> Result<Self, HiddenInputError> {
        let mut guard = Self {
            originals: Vec::with_capacity(HANDLED_SIGNALS.len()),
        };
        for signal in HANDLED_SIGNALS {
            // SAFETY: zero is a valid starting representation before all public
            // fields and the signal mask are initialized below.
            let mut action = unsafe { std::mem::zeroed::<libc::sigaction>() };
            action.sa_sigaction = record_signal as *const () as libc::sighandler_t;
            action.sa_flags = 0;
            // SAFETY: `sa_mask` points to writable signal-set storage.
            if unsafe { libc::sigemptyset(&raw mut action.sa_mask) } == -1 {
                return Err(HiddenInputError::IoFailure);
            }
            let mut original = std::mem::MaybeUninit::<libc::sigaction>::uninit();
            // SAFETY: `action` is completely initialized and `original` points
            // to writable storage for the previous disposition.
            if unsafe { libc::sigaction(signal, &raw const action, original.as_mut_ptr()) } == -1 {
                return Err(HiddenInputError::IoFailure);
            }
            // SAFETY: successful `sigaction` initialized the previous disposition.
            guard
                .originals
                .push((signal, unsafe { original.assume_init() }));
        }
        Ok(guard)
    }

    fn restore(&mut self) -> Result<(), HiddenInputError> {
        while let Some((signal, original)) = self.originals.pop() {
            // SAFETY: each saved disposition was returned by `sigaction` for the
            // matching signal; a null output pointer requests restoration only.
            if unsafe { libc::sigaction(signal, &raw const original, std::ptr::null_mut()) } == -1 {
                self.originals.push((signal, original));
                return Err(HiddenInputError::IoFailure);
            }
        }
        Ok(())
    }
}

impl Drop for SignalGuard {
    fn drop(&mut self) {
        let _ = self.restore();
        PENDING_SIGNAL.store(0, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs::File,
        io::{Read, Write},
        os::fd::{AsRawFd, FromRawFd, OwnedFd},
        sync::Arc,
        thread,
        time::Duration,
    };

    use super::*;

    fn pseudo_terminal() -> (File, Arc<OwnedFd>) {
        let mut master = -1;
        let mut slave = -1;
        // SAFETY: both output pointers are valid; null optional parameters ask
        // the OS to choose the name, termios state, and window size.
        assert_eq!(
            unsafe {
                libc::openpty(
                    &raw mut master,
                    &raw mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            0
        );
        // SAFETY: successful `openpty` returned two newly owned descriptors.
        let master = File::from(unsafe { OwnedFd::from_raw_fd(master) });
        // SAFETY: as above, ownership of the slave descriptor is transferred once.
        let slave = Arc::new(unsafe { OwnedFd::from_raw_fd(slave) });
        (master, slave)
    }

    fn echo_enabled(descriptor: libc::c_int) -> bool {
        let mut state = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: `state` is writable and the test owns a live terminal descriptor.
        assert_eq!(
            unsafe { libc::tcgetattr(descriptor, state.as_mut_ptr()) },
            0
        );
        // SAFETY: successful `tcgetattr` initialized the value.
        unsafe { state.assume_init() }.c_lflag & libc::ECHO != 0
    }

    fn wait_until_echo_is_disabled(descriptor: libc::c_int) {
        for _ in 0..200 {
            if !echo_enabled(descriptor) {
                return;
            }
            thread::sleep(Duration::from_millis(5));
        }
        panic!("terminal echo was not disabled");
    }

    #[test]
    fn hides_input_and_restores_terminal_state() {
        let (mut master, slave) = pseudo_terminal();
        let reader = Arc::clone(&slave);
        let handle = thread::spawn(move || read_hidden_fd(reader.as_raw_fd(), 256));
        wait_until_echo_is_disabled(slave.as_raw_fd());

        master.write_all(b"CANARY-$() `secret`\n").unwrap();
        let input = handle.join().unwrap().unwrap();
        assert!(
            input.as_slice() == b"CANARY-$() `secret`",
            "hidden terminal byte preservation failed"
        );
        assert!(echo_enabled(slave.as_raw_fd()));

        let flags = unsafe { libc::fcntl(master.as_raw_fd(), libc::F_GETFL) };
        assert_ne!(flags, -1);
        // SAFETY: the descriptor is live and the existing flags are preserved.
        assert_ne!(
            unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) },
            -1
        );
        let mut transcript = [0_u8; 128];
        match master.read(&mut transcript) {
            Ok(length) => {
                if transcript[..length]
                    .windows(6)
                    .any(|part| part == b"CANARY")
                {
                    panic!("terminal transcript exposed secret bytes");
                }
            }
            Err(error) => assert_eq!(error.kind(), io::ErrorKind::WouldBlock),
        }
    }

    #[test]
    fn handled_interrupt_restores_terminal_state() {
        let (_master, slave) = pseudo_terminal();
        let reader = Arc::clone(&slave);
        let (thread_sender, thread_receiver) = std::sync::mpsc::channel();
        let handle = thread::spawn(move || {
            // SAFETY: `pthread_self` has no preconditions.
            thread_sender.send(unsafe { libc::pthread_self() }).unwrap();
            read_hidden_fd(reader.as_raw_fd(), 256)
        });
        let reader_thread = thread_receiver.recv().unwrap();
        wait_until_echo_is_disabled(slave.as_raw_fd());
        // SAFETY: the target thread remains live until the blocked read returns.
        assert_eq!(
            unsafe { libc::pthread_kill(reader_thread, libc::SIGINT) },
            0
        );

        assert_eq!(handle.join().unwrap(), Err(HiddenInputError::Interrupted));
        assert!(echo_enabled(slave.as_raw_fd()));
    }
}
