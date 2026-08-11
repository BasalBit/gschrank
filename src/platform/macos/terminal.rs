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
    ready: impl FnOnce() -> Result<(), HiddenInputError>,
) -> Result<Zeroizing<Vec<u8>>, HiddenInputError> {
    read_hidden_fd(libc::STDIN_FILENO, maximum_bytes, ready)
}

fn read_hidden_fd(
    descriptor: libc::c_int,
    maximum_bytes: usize,
    ready: impl FnOnce() -> Result<(), HiddenInputError>,
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
    let controls = terminal.input_controls();
    let input = ready().and_then(|()| read_line_bytes(descriptor, maximum_bytes, controls));
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
    controls: InputControls,
) -> Result<Zeroizing<Vec<u8>>, HiddenInputError> {
    let retained_limit = maximum_bytes.saturating_add(1);
    let mut input = Zeroizing::new(Vec::new());
    let mut literal_next = false;
    let mut overflowed = false;
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
            if literal_next {
                literal_next = false;
            } else if controls.literal_next == Some(byte) {
                literal_next = true;
                continue;
            } else if byte == b'\n' || controls.eof == Some(byte) {
                break;
            } else if controls.erase == Some(byte) {
                erase_last_character(&mut input);
                continue;
            } else if controls.word_erase == Some(byte) {
                erase_last_word(&mut input, controls.alternate_word_erase);
                continue;
            } else if controls.kill == Some(byte) {
                input.clear();
                overflowed = false;
                continue;
            }
            if input.len() < retained_limit {
                input.push(byte);
            } else {
                overflowed = true;
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
    if overflowed {
        input.resize(retained_limit, 0);
    }
    Ok(input)
}

fn erase_last_character(input: &mut Vec<u8>) {
    let Some(removed) = input.pop() else {
        return;
    };
    if removed.is_ascii() {
        return;
    }
    while input.last().is_some_and(|byte| byte & 0xc0 == 0x80) {
        input.pop();
    }
    if input.last().is_some_and(|byte| !byte.is_ascii()) {
        input.pop();
    }
}

fn erase_last_word(input: &mut Vec<u8>, alternate: bool) {
    while input
        .last()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        erase_last_character(input);
    }
    if alternate && !input.is_empty() {
        erase_last_character(input);
    }
    let class = alternate.then(|| last_character_is_word(input));
    while input
        .last()
        .is_some_and(|byte| !matches!(byte, b' ' | b'\t'))
        && class.is_none_or(|class| last_character_is_word(input) == class)
    {
        erase_last_character(input);
    }
}

fn last_character_is_word(input: &[u8]) -> bool {
    std::str::from_utf8(input)
        .ok()
        .and_then(|input| input.chars().next_back())
        .is_some_and(|character| character.is_alphanumeric() || character == '_')
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
        hidden.c_lflag &= !(libc::ECHO | libc::ECHONL | libc::ICANON | libc::IEXTEN);
        hidden.c_cc[libc::VMIN] = 1;
        hidden.c_cc[libc::VTIME] = 0;
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

    fn input_controls(&self) -> InputControls {
        let extended = self.original.c_lflag & libc::IEXTEN != 0;
        InputControls {
            eof: enabled_control(self.original.c_cc[libc::VEOF]),
            erase: enabled_control(self.original.c_cc[libc::VERASE]),
            kill: enabled_control(self.original.c_cc[libc::VKILL]),
            literal_next: extended
                .then_some(self.original.c_cc[libc::VLNEXT])
                .and_then(enabled_control),
            word_erase: extended
                .then_some(self.original.c_cc[libc::VWERASE])
                .and_then(enabled_control),
            alternate_word_erase: self.original.c_lflag & libc::ALTWERASE != 0,
        }
    }
}

fn enabled_control(control: libc::cc_t) -> Option<libc::cc_t> {
    (control != libc::_POSIX_VDISABLE).then_some(control)
}

#[derive(Clone, Copy)]
struct InputControls {
    eof: Option<libc::cc_t>,
    erase: Option<libc::cc_t>,
    kill: Option<libc::cc_t>,
    literal_next: Option<libc::cc_t>,
    word_erase: Option<libc::cc_t>,
    alternate_word_erase: bool,
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

    fn terminal_control(descriptor: libc::c_int, index: usize) -> libc::cc_t {
        let mut state = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: `state` is writable and the test owns a live terminal descriptor.
        assert_eq!(
            unsafe { libc::tcgetattr(descriptor, state.as_mut_ptr()) },
            0
        );
        // SAFETY: successful `tcgetattr` initialized the value.
        unsafe { state.assume_init() }.c_cc[index]
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
        let handle = thread::spawn(move || read_hidden_fd(reader.as_raw_fd(), 256, || Ok(())));
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
            read_hidden_fd(reader.as_raw_fd(), 256, || Ok(()))
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

    #[test]
    fn hidden_input_accepts_values_larger_than_the_terminal_canonical_buffer() {
        let (mut master, slave) = pseudo_terminal();
        let reader = Arc::clone(&slave);
        let (result_sender, result_receiver) = std::sync::mpsc::channel();
        let handle = thread::spawn(move || {
            let descriptor = reader.as_raw_fd();
            result_sender
                .send(read_hidden_fd(descriptor, 8 * 1024, || {
                    assert!(!echo_enabled(descriptor));
                    Ok(())
                }))
                .unwrap();
        });
        wait_until_echo_is_disabled(slave.as_raw_fd());
        let jwt = vec![b'x'; 4 * 1024];
        master.write_all(&jwt).unwrap();
        master.write_all(b"\n").unwrap();

        let Ok(result) = result_receiver.recv_timeout(Duration::from_secs(2)) else {
            drop(master);
            let _ = result_receiver.recv_timeout(Duration::from_secs(1));
            handle.join().unwrap();
            panic!("hidden input remained blocked after Enter");
        };
        handle.join().unwrap();
        assert_eq!(result.unwrap().as_slice(), jwt);
        assert!(echo_enabled(slave.as_raw_fd()));
    }

    #[test]
    fn manual_editing_removes_complete_utf8_characters_and_words() {
        let mut input = "token ü".as_bytes().to_vec();
        erase_last_character(&mut input);
        assert_eq!(input, b"token ");

        input.extend_from_slice("JWT".as_bytes());
        erase_last_word(&mut input, false);
        assert_eq!(input, b"token ");

        input.extend_from_slice(b"name.token");
        erase_last_word(&mut input, true);
        assert_eq!(input, b"token name.");

        input = b"name.".to_vec();
        erase_last_word(&mut input, true);
        assert!(input.is_empty());
    }

    #[test]
    fn literal_next_quotes_newline_and_erase_controls() {
        let (mut master, slave) = pseudo_terminal();
        let literal_next = terminal_control(slave.as_raw_fd(), libc::VLNEXT);
        let erase = terminal_control(slave.as_raw_fd(), libc::VERASE);
        let reader = Arc::clone(&slave);
        let handle = thread::spawn(move || read_hidden_fd(reader.as_raw_fd(), 256, || Ok(())));
        wait_until_echo_is_disabled(slave.as_raw_fd());
        master.write_all(b"before").unwrap();
        master.write_all(&[literal_next, b'\n']).unwrap();
        master.write_all(b"after").unwrap();
        master.write_all(&[literal_next, erase, b'\n']).unwrap();

        let mut expected = b"before\nafter".to_vec();
        expected.push(erase);
        assert_eq!(handle.join().unwrap().unwrap().as_slice(), expected);
        assert!(echo_enabled(slave.as_raw_fd()));
    }

    #[test]
    fn editing_does_not_turn_oversized_input_into_truncated_success() {
        let (mut master, slave) = pseudo_terminal();
        let erase = terminal_control(slave.as_raw_fd(), libc::VERASE);
        let reader = Arc::clone(&slave);
        let handle = thread::spawn(move || read_hidden_fd(reader.as_raw_fd(), 4, || Ok(())));
        wait_until_echo_is_disabled(slave.as_raw_fd());
        master.write_all(b"abcdef").unwrap();
        master.write_all(&[erase, b'\n']).unwrap();

        assert_eq!(handle.join().unwrap().unwrap().len(), 5);
        assert!(echo_enabled(slave.as_raw_fd()));
    }

    #[test]
    fn eof_and_oversized_input_restore_terminal_state() {
        let (master, slave) = pseudo_terminal();
        let reader = Arc::clone(&slave);
        let handle = thread::spawn(move || read_hidden_fd(reader.as_raw_fd(), 256, || Ok(())));
        wait_until_echo_is_disabled(slave.as_raw_fd());
        drop(master);
        assert_eq!(handle.join().unwrap().unwrap().as_slice(), b"");
        assert!(echo_enabled(slave.as_raw_fd()));

        let (mut master, slave) = pseudo_terminal();
        let reader = Arc::clone(&slave);
        let handle = thread::spawn(move || read_hidden_fd(reader.as_raw_fd(), 4, || Ok(())));
        wait_until_echo_is_disabled(slave.as_raw_fd());
        master.write_all(b"abcdef\n").unwrap();
        assert_eq!(handle.join().unwrap().unwrap().as_slice(), b"abcde");
        assert!(echo_enabled(slave.as_raw_fd()));
    }

    #[test]
    fn unwinding_drops_the_terminal_guard_and_restores_echo() {
        let (_master, slave) = pseudo_terminal();
        let result = std::panic::catch_unwind({
            let slave = Arc::clone(&slave);
            move || {
                let _guard = TerminalGuard::disable_echo(slave.as_raw_fd()).unwrap();
                assert!(!echo_enabled(slave.as_raw_fd()));
                panic!("injected hidden-input panic");
            }
        });
        assert!(result.is_err());
        assert!(echo_enabled(slave.as_raw_fd()));
    }
}
