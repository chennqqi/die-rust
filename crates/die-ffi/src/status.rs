//! Status code definitions and name lookup.

/// Status codes matching `diec.h` definitions.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiecStatus {
    /// Success.
    Ok = 0,
    /// Invalid pointer, length, flag or state.
    InvalidArgument = 1,
    /// Caller requested incompatible ABI.
    AbiMismatch = 2,
    /// Invalid UTF-8 input.
    InvalidUtf8 = 3,
    /// File or directory I/O failure.
    Io = 4,
    /// Rule database load or validation failure.
    Database = 5,
    /// Unsupported format, syntax or feature.
    Unsupported = 6,
    /// Byte/entry/depth/memory budget exceeded.
    LimitExceeded = 7,
    /// Cancel token was requested.
    Cancelled = 8,
    /// Deadline expired.
    Timeout = 9,
    /// Rule parse or runtime error.
    Script = 10,
    /// Thread-affine handle used on wrong thread.
    WrongThread = 11,
    /// Scanner reentry or concurrent call.
    Busy = 12,
    /// Unwind panic caught at boundary.
    Panic = 13,
    /// Internal invariant violated.
    Internal = 14,
    /// Recoverable allocation failure.
    AllocationFailed = 15,
}

impl DiecStatus {
    /// Convert a raw u32 status to DiecStatus, or None if unknown.
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Ok),
            1 => Some(Self::InvalidArgument),
            2 => Some(Self::AbiMismatch),
            3 => Some(Self::InvalidUtf8),
            4 => Some(Self::Io),
            5 => Some(Self::Database),
            6 => Some(Self::Unsupported),
            7 => Some(Self::LimitExceeded),
            8 => Some(Self::Cancelled),
            9 => Some(Self::Timeout),
            10 => Some(Self::Script),
            11 => Some(Self::WrongThread),
            12 => Some(Self::Busy),
            13 => Some(Self::Panic),
            14 => Some(Self::Internal),
            15 => Some(Self::AllocationFailed),
            _ => None,
        }
    }

    /// Get the canonical name string for a status code.
    pub fn name(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::InvalidArgument => "INVALID_ARGUMENT",
            Self::AbiMismatch => "ABI_MISMATCH",
            Self::InvalidUtf8 => "INVALID_UTF8",
            Self::Io => "IO",
            Self::Database => "DATABASE",
            Self::Unsupported => "UNSUPPORTED",
            Self::LimitExceeded => "LIMIT_EXCEEDED",
            Self::Cancelled => "CANCELLED",
            Self::Timeout => "TIMEOUT",
            Self::Script => "SCRIPT",
            Self::WrongThread => "WRONG_THREAD",
            Self::Busy => "BUSY",
            Self::Panic => "PANIC",
            Self::Internal => "INTERNAL",
            Self::AllocationFailed => "ALLOCATION_FAILED",
        }
    }
}

impl From<DiecStatus> for u32 {
    fn from(s: DiecStatus) -> u32 {
        s as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_round_trip() {
        for i in 0..=15u32 {
            let s = DiecStatus::from_u32(i).unwrap();
            assert_eq!(u32::from(s), i);
        }
    }

    #[test]
    fn unknown_status_is_none() {
        assert!(DiecStatus::from_u32(16).is_none());
        assert!(DiecStatus::from_u32(100).is_none());
    }

    #[test]
    fn status_names_are_nonempty() {
        for i in 0..=15u32 {
            let s = DiecStatus::from_u32(i).unwrap();
            assert!(!s.name().is_empty());
        }
    }
}
