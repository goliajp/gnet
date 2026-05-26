//! RFC 3339 UTC timestamps from `std::time::SystemTime` — no chrono.
//!
//! Format: `YYYY-MM-DDTHH:MM:SSZ` (seconds resolution; gnet-discover never
//! needs sub-second precision in audit fields).

use std::time::{SystemTime, UNIX_EPOCH};

/// Current UTC time as an RFC 3339 string with second resolution.
pub fn now_rfc3339() -> String {
    rfc3339_from_unix(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
    )
}

/// Format a unix epoch second as `YYYY-MM-DDTHH:MM:SSZ`.
///
/// Civil-from-days algorithm by Howard Hinnant — date.h / public domain.
/// Valid for any year in [-32767, 32767].
pub fn rfc3339_from_unix(epoch_sec: i64) -> String {
    let (mut days, mut secs) = (epoch_sec.div_euclid(86_400), epoch_sec.rem_euclid(86_400));
    let h = secs / 3600;
    secs %= 3600;
    let m = secs / 60;
    let s = secs % 60;

    // shift to era starting from year 0 (March 1)
    days += 719_468;
    let era = days.div_euclid(146_097);
    let doe = days.rem_euclid(146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + if mo <= 2 { 1 } else { 0 };

    format!("{year:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_zero() {
        assert_eq!(rfc3339_from_unix(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn known_dates() {
        // 2026-05-26 00:00:00 UTC
        assert_eq!(rfc3339_from_unix(1_779_753_600), "2026-05-26T00:00:00Z");
        // 2000-02-29 12:34:56 UTC (leap year edge)
        assert_eq!(rfc3339_from_unix(951_827_696), "2000-02-29T12:34:56Z");
        // 2099-12-31 23:59:59 UTC
        assert_eq!(rfc3339_from_unix(4_102_444_799), "2099-12-31T23:59:59Z");
    }

    #[test]
    fn now_format_shape() {
        let s = now_rfc3339();
        assert_eq!(s.len(), 20);
        assert!(s.ends_with('Z'));
        assert_eq!(&s[4..5], "-");
        assert_eq!(&s[10..11], "T");
    }
}
