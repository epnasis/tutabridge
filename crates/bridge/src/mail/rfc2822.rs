use base64::Engine;
use tutasdk::entities::generated::tutanota::{Mail, MailAddress, MailDetails, TutanotaFile};

/// One decrypted attachment as it lands in the RFC 2822 we serve over IMAP:
/// the [`TutanotaFile`] entity (for name + MIME type + cid) and the raw
/// decrypted bytes (for the body of the part).
pub type AttachmentPart<'a> = (&'a TutanotaFile, &'a [u8]);

/// Headers copied from the sender's original message into the one we build.
///
/// The message served over IMAP is a RECONSTRUCTION, not the original: the
/// body is re-encoded, the MIME boundary is ours, the Message-ID is ours. So
/// any header describing the message's own structure would describe a body
/// that no longer exists — `Content-Type` would contradict the part we just
/// wrote, a second `Message-ID` would collide with the one clients already
/// keyed on, and `DKIM-Signature`/`Received` cannot verify against a body
/// they never covered. What survives that rule is the narrow set of headers
/// stating a fact about the mail's PROVENANCE, which is exactly what
/// downstream filtering (mail-client rules, sweepy) needs and cannot infer.
const PASSTHROUGH_HEADERS: &[&str] = &[
    "list-unsubscribe",
    "list-unsubscribe-post",
    "list-id",
    "precedence",
    "auto-submitted",
];

/// The one header in a served message that the bridge vouches for: Tuta's
/// sender authentication verdicts (see [`authentication_header_value`]). Guarantee: if this header
/// is present, the bridge wrote it, and exactly one copy exists — enforced by
/// [`prepend_authentication_header`], which removes every same-named field
/// before writing its own.
pub const AUTHENTICATION_HEADER: &str = "X-Tutabridge-Authentication";

/// Bumped whenever the value format of [`AUTHENTICATION_HEADER`] changes, so
/// a client can tell which grammar it is reading.
const AUTHENTICATION_HEADER_VERSION: u32 = 1;

/// `MailAuthenticationStatus` in Tuta's `TutanotaConstants.ts`.
fn mail_authentication_status_name(code: i64) -> Option<&'static str> {
    match code {
        0 => Some("authenticated"),
        1 => Some("hard_fail"),
        2 => Some("soft_fail"),
        3 => Some("invalid_mail_from"),
        4 => Some("missing_mail_from"),
        _ => None,
    }
}

/// `EncryptionAuthStatus` in Tuta's `TutanotaConstants.ts`.
fn encryption_auth_status_name(code: i64) -> Option<&'static str> {
    match code {
        0 => Some("rsa_no_authentication"),
        1 => Some("tutacrypt_authentication_succeeded"),
        2 => Some("tutacrypt_authentication_failed"),
        3 => Some("aes_no_authentication"),
        4 => Some("tutacrypt_sender"),
        5 => Some("rsa_despite_tutacrypt"),
        _ => None,
    }
}

/// A code Tuta added after this table was written is reported as such rather
/// than folded into a known name or into `unknown`, which means "absent".
fn status_token(code: Option<i64>, name: fn(i64) -> Option<&'static str>) -> String {
    match code {
        None => "unknown".to_owned(),
        Some(code) => name(code)
            .map(str::to_owned)
            .unwrap_or_else(|| format!("unrecognized-{code}")),
    }
}

/// The value of [`AUTHENTICATION_HEADER`]. Each field names where it comes
/// from, because the two do not share an origin:
///
/// - `status`: `MailDetails.authStatus`, written by Tuta's mail server. Not
///   `Mail.authStatus`: the details field is the one the Tuta web client's
///   "could not verify sender" banner reads
///   (`MailViewerViewModel.checkMailAuthenticationStatus`). Without details
///   the verdict is not known and says so.
/// - `encryption-auth`: `Mail.encryptionAuthStatus`, a client-side verdict,
///   not the server's: the SDK computes it while decrypting a mail that still
///   carries a bucket key, otherwise it is the value a Tuta client (this one
///   or another) stored on the mail after doing the same.
///
/// `Mail.phishingStatus` is deliberately absent: Tuta clients set it after
/// delivery, and a rendition is immutable once served, so it would go stale.
fn authentication_header_value(mail: &Mail, details: Option<&MailDetails>) -> String {
    format!(
        "status={}; status-source=tuta-server; encryption-auth={}; \
         encryption-auth-source=tuta-client-decrypt; v={}",
        status_token(
            details.map(|d| d.authStatus),
            mail_authentication_status_name
        ),
        status_token(mail.encryptionAuthStatus, encryption_auth_status_name),
        AUTHENTICATION_HEADER_VERSION,
    )
}

/// Whether a raw header line opens a field named [`AUTHENTICATION_HEADER`].
///
/// Deliberately broader than RFC 5322, so that no reader finds a copy this
/// misses:
/// - any [`is_line_break`] character inside the line counts as a break, since
///   some readers split on a bare CR or LF, or on Unicode line separators;
/// - a segment without a colon counts by its whole text, since a reader that
///   unfolds before splitting would join `Name` and a following ` : value`;
/// - names compare after Unicode uppercasing, the rule the IMAP layer's
///   HEADER.FIELDS filter uses, under which a dotless `ı` matches `I`.
fn opens_authentication_field(line: &str) -> bool {
    let ours = AUTHENTICATION_HEADER.to_uppercase();
    line.split(is_line_break).any(|segment| {
        let name = segment.split(':').next().unwrap_or("");
        // Trim everything but visible ASCII: readers' trims differ (Python's
        // `strip` and Java's `trim` drop control characters, JavaScript's
        // drops U+FEFF), so take the widest.
        name.trim_matches(|c: char| !c.is_ascii_graphic())
            .to_uppercase()
            == ours
    })
}

/// Remove every field named [`AUTHENTICATION_HEADER`] from the message's
/// header block, including folded continuation lines, then write ours as the
/// first header.
///
/// Every header we emit is ours, but several carry sender-controlled text
/// (addresses, the allowlisted provenance headers). This pass is what turns
/// "no code path writes a second copy" from an argument into a property of
/// the output.
pub(crate) fn prepend_authentication_header(message: &str, value: &str) -> String {
    let (head, body) = match message.find("\r\n\r\n") {
        Some(end) => message.split_at(end + 2),
        None => (message, ""),
    };

    let mut out = String::with_capacity(message.len() + 128);
    out.push_str(&format!("{AUTHENTICATION_HEADER}: {value}\r\n"));

    // A matching field line takes its continuations with it. A matching
    // continuation line goes alone: what follows it still belongs to the
    // field it continues (a folded `To:` keeps its other recipients).
    let mut dropping_field = false;
    for line in head.split_inclusive('\n') {
        let continuation = line.starts_with(' ') || line.starts_with('\t');
        if !continuation {
            dropping_field = opens_authentication_field(line);
        }
        if !dropping_field && !opens_authentication_field(line) {
            out.push_str(line);
        }
    }
    out.push_str(body);
    out
}

/// The sender's original header block, as Tuta stored it with the mail.
///
/// Mirrors how the body is read: the SDK's entity facade decompresses LZ4
/// fields during decryption, so `compressedHeaders` arrives as plain text and
/// is preferred when present. Absent for mail that never had RFC 2822 headers
/// (Tuta-internal mail), which is normal and not an error.
fn original_headers(details: &MailDetails) -> Option<&str> {
    let header = details.headers.as_ref()?;
    header
        .compressedHeaders
        .as_deref()
        .or(header.headers.as_deref())
}

/// Extract the allowlisted headers from an original header block, preserving
/// RFC 5322 §2.2.3 folded continuation lines (List-Unsubscribe values wrap
/// routinely).
///
/// Parsing line-by-line and re-emitting only whole allowlisted fields is also
/// what makes this safe: header values are sender-controlled, so a value
/// carrying an embedded newline plus `Content-Type: …` must not be able to
/// smuggle a structural header into our message. Such a line is simply a
/// non-allowlisted field name to this loop, and is dropped.
pub(crate) fn passthrough_headers(raw: &str) -> Vec<String> {
    let mut kept: Vec<String> = Vec::new();
    let mut keeping = false;

    for line in raw.lines() {
        if line.is_empty() {
            break; // end of the header block; a body must not be re-parsed
        }

        if line.starts_with(' ') || line.starts_with('\t') {
            if keeping {
                if let Some(last) = kept.last_mut() {
                    last.push_str("\r\n");
                    last.push_str(&sanitize_header_line(line));
                }
            }
            continue;
        }

        // A line opening with any other whitespace or line break is neither
        // a field nor a continuation; kept, it would sanitize into a leading
        // space and fold itself onto whatever header we emitted before it.
        if line.starts_with(|c: char| c.is_whitespace() || is_line_break(c)) {
            keeping = false;
            continue;
        }

        keeping = match line.split_once(':') {
            Some((name, _)) => {
                PASSTHROUGH_HEADERS.contains(&name.trim().to_ascii_lowercase().as_str())
            }
            None => false,
        };
        if keeping {
            kept.push(sanitize_header_line(line));
        }
    }

    // A field is copied as-is, so an RFC 2047 encoded-word in it reaches a
    // client that decodes it, possibly into a line break followed by a line
    // of the sender's choosing. Clients decode more leniently than any check
    // we could write, so fail closed: drop every field carrying one.
    // Non-ASCII goes for the same reason: a reader may decode it as Latin-1
    // (UTF-8 `Å` is `C3 85`, and 0x85 is NEL) or trim characters we don't.
    kept.retain(|field| {
        let carries_encoded_word = field.contains(ENCODED_WORD_START);
        let plain = is_plain_header_text(field)
            && field.split("\r\n").all(|line| line.len() <= MAX_LINE_LEN);
        if carries_encoded_word || !plain {
            // Names only, as in `field_names`: values are message content.
            log::debug!(
                "dropped provenance header {} carrying {}",
                field.split(':').next().unwrap_or("").trim(),
                if plain {
                    "an encoded-word"
                } else {
                    "non-ASCII text or an over-long line"
                }
            );
        }
        plain && !carries_encoded_word
    });
    kept
}

/// RFC 5322 §2.1.1: a line is at most 998 octets.
const MAX_LINE_LEN: usize = 998;

/// Printable ASCII, plus the CRLF + SP/HT of folding. Every top-level header
/// line we emit is made of these alone, which is what ends the hunt for
/// characters some reader treats as a break or as trimmable: Unicode
/// separators, byte 0x85 seen through Latin-1, U+FEFF, compatibility forms.
fn is_plain_header_text(text: &str) -> bool {
    text.chars()
        .all(|c| c.is_ascii_graphic() || matches!(c, ' ' | '\t' | '\r' | '\n'))
}

/// Where an RFC 2047 encoded-word begins. Sender text containing it is never
/// emitted as-is: a decoding client would expand it.
const ENCODED_WORD_START: &str = "=?";

/// Every character some reader of the served message treats as a line break:
/// CR and LF, plus the rest of what Python's `str.splitlines` and
/// Unicode-aware regexes split on. Sender text containing one of these must
/// never reach a header line raw, or that reader sees a header of its own.
fn is_line_break(c: char) -> bool {
    matches!(
        c,
        '\n' | '\x0b'
            | '\x0c'
            | '\r'
            | '\x1c'
            | '\x1d'
            | '\x1e'
            | '\u{85}'
            | '\u{2028}'
            | '\u{2029}'
    )
}

/// A stray line break inside a field would end it, or the header block, early.
/// `str::lines` only strips a trailing CR, so anything embedded is neutralised.
/// Other control characters go too: readers disagree on whether they are
/// whitespace, and a header never needs one. Tab stays — it folds lines.
fn sanitize_header_line(line: &str) -> String {
    line.replace(
        |c: char| is_line_break(c) || (c.is_control() && c != '\t'),
        " ",
    )
}

/// Field names present in an original header block, for diagnostics. Names
/// only — never values, which are message content.
pub(crate) fn field_names(raw: &str) -> Vec<&str> {
    raw.lines()
        .take_while(|line| !line.is_empty())
        .filter(|line| !line.starts_with(' ') && !line.starts_with('\t'))
        .filter_map(|line| line.split_once(':').map(|(name, _)| name.trim()))
        .collect()
}

pub fn mail_to_rfc2822(
    mail: &Mail,
    details: Option<&MailDetails>,
    attachments: &[AttachmentPart<'_>],
) -> String {
    let mut msg = String::with_capacity(4096);

    let date_str = format_rfc2822_date(mail.receivedDate.as_millis());
    msg.push_str(&format!("Date: {}\r\n", date_str));

    msg.push_str(&address_field("From", [&mail.sender]));

    msg.push_str(&format!(
        "Subject: {}\r\n",
        encode_header_value(&mail.subject)
    ));

    if let Some(details) = details {
        if !details.recipients.toRecipients.is_empty() {
            msg.push_str(&address_field("To", &details.recipients.toRecipients));
        }
        if !details.recipients.ccRecipients.is_empty() {
            msg.push_str(&address_field("Cc", &details.recipients.ccRecipients));
        }
        // Only the sender's own copies (drafts, sent mail) carry Bcc; a draft
        // reopened without it would be sent without those recipients.
        if !details.recipients.bccRecipients.is_empty() {
            msg.push_str(&address_field("Bcc", &details.recipients.bccRecipients));
        }
    } else if let Some(ref first) = mail.firstRecipient {
        msg.push_str(&address_field("To", [first]));
    }

    if let Some(ref id) = mail._id {
        msg.push_str(&format!(
            "Message-ID: <{}.{}@tutabridge.local>\r\n",
            // Server-assigned, but the SDK does not validate their shape.
            printable_ascii(&id.list_id.to_string()),
            printable_ascii(&id.element_id.to_string())
        ));
    }

    if let Some(raw) = details.and_then(original_headers) {
        let kept = passthrough_headers(raw);
        if kept.is_empty() {
            // "Why is List-Unsubscribe missing?" has three very different
            // answers — the sender never sent one, we failed to parse the
            // block, or `passthrough_headers` dropped it on purpose (logged
            // there) — and from outside they look identical. Field names are
            // not message content, so logging them is safe.
            log::debug!(
                "no provenance headers among: {}",
                field_names(raw).join(", ")
            );
        }
        for header in kept {
            msg.push_str(&header);
            msg.push_str("\r\n");
        }
    }

    msg.push_str("MIME-Version: 1.0\r\n");

    let body_text = details
        .and_then(|d| d.body.compressedText.as_deref().or(d.body.text.as_deref()))
        .unwrap_or("<p>(No body available)</p>");

    if attachments.is_empty() {
        msg.push_str("Content-Type: text/html; charset=UTF-8\r\n");
        msg.push_str("Content-Transfer-Encoding: base64\r\n");
        msg.push_str("\r\n");
        msg.push_str(&base64_encode_body(body_text.as_bytes()));
        msg.push_str("\r\n");
    } else {
        // The boundary is derived from the mail's element id so the same
        // mail always produces the same MIME boundary — keeps `.eml.enc`
        // bytes stable across rewrites.
        let boundary = build_boundary(mail);
        msg.push_str(&format!(
            "Content-Type: multipart/mixed; boundary=\"{}\"\r\n",
            boundary
        ));
        msg.push_str("\r\n");
        msg.push_str("This is a multi-part message in MIME format.\r\n");

        msg.push_str(&format!("--{}\r\n", boundary));
        msg.push_str("Content-Type: text/html; charset=UTF-8\r\n");
        msg.push_str("Content-Transfer-Encoding: base64\r\n\r\n");
        msg.push_str(&base64_encode_body(body_text.as_bytes()));
        msg.push_str("\r\n");

        for (file, data) in attachments {
            msg.push_str(&format!("--{}\r\n", boundary));
            let mime = file
                .mimeType
                .as_deref()
                .unwrap_or("application/octet-stream");
            let name_encoded = encode_header_value(&file.name);
            msg.push_str(&format!(
                "Content-Type: {}; name=\"{}\"\r\n",
                mime, name_encoded
            ));
            msg.push_str("Content-Transfer-Encoding: base64\r\n");
            msg.push_str(&format!(
                "Content-Disposition: attachment; filename=\"{}\"\r\n",
                name_encoded
            ));
            if let Some(ref cid) = file.cid {
                // Some Tuta files (inline images) carry a Content-ID — propagate
                // it so HTML `<img src="cid:…">` references still resolve.
                msg.push_str(&format!("Content-ID: <{}>\r\n", cid));
            }
            msg.push_str("\r\n");
            msg.push_str(&base64_encode_body(data));
            msg.push_str("\r\n");
        }
        msg.push_str(&format!("--{}--\r\n", boundary));
    }

    prepend_authentication_header(&msg, &authentication_header_value(mail, details))
}

/// Build a MIME boundary that is stable for a given mail and unlikely to
/// collide with payload bytes. Format: `=_TutaBridge_<list>_<elem>` where the
/// ids are the mail's `IdTuple` — they contain only base64-ext characters
/// (so safe in a Content-Type header) and uniquely identify the mail.
fn build_boundary(mail: &Mail) -> String {
    // The ids are server-assigned base64ext, but the SDK does not check, so
    // hold them to it: anything else could break the quoted parameter.
    let base64ext = |id: String| -> String {
        id.chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect()
    };
    let mut boundary = if let Some(ref id) = mail._id {
        format!(
            "=_TutaBridge_{}_{}",
            base64ext(id.list_id.to_string()),
            base64ext(id.element_id.to_string())
        )
    } else {
        "=_TutaBridge_unknown".to_owned()
    };
    boundary.truncate(MAX_BOUNDARY_LEN);
    boundary
}

/// RFC 2046 §5.1.1.
const MAX_BOUNDARY_LEN: usize = 70;

/// An address for search and MCP output, where it is data, not a header line.
pub(crate) fn format_address(addr: &MailAddress) -> String {
    if addr.name.is_empty() {
        addr.address.clone()
    } else {
        format!("{} <{}>", encode_header_value(&addr.name), addr.address)
    }
}

/// The longest address SMTP carries (RFC 5321 §4.5.3.1.3).
const MAX_ADDRESS_LEN: usize = 254;

/// An address as it goes on a header line of the rendition, as the tokens
/// [`address_field`] lays out. It is
/// sender-controlled and cannot be encoded, so it is held to
/// [`is_plain_header_text`]: anything but printable ASCII becomes `?`, an
/// encoded-word start is broken up (a lenient decoder would expand it), and
/// it is cut at [`MAX_ADDRESS_LEN`] so a relay splitting long lines cannot
/// pick where. Cost: an internationalized (RFC 6531) address is shown
/// mangled, and a reply to it from the served copy would not reach the sender.
fn header_address_tokens(addr: &MailAddress) -> Vec<String> {
    // Mapping first: `?` is one of the characters it produces.
    let mut address = printable_ascii(&addr.address).replace(ENCODED_WORD_START, "=_");
    address.truncate(MAX_ADDRESS_LEN);
    let name = if opens_authentication_field(&addr.name) {
        // Folded to the start of a line, it would be stripped as a copy of
        // our header; encoded, it can never look like one.
        encoded_word(&sanitize_header_line(&addr.name))
    } else {
        encode_header_value(&addr.name)
    };
    if addr.name.is_empty() && !opens_authentication_field(&address) {
        vec![address]
    } else if addr.name.is_empty() {
        // Same for a bare address: in angle brackets a line it starts opens
        // with `<`, so the stripper never takes the recipients folded with it.
        vec![format!("<{address}>")]
    } else {
        vec![name, format!("<{address}>")]
    }
}

/// How long a plain address-field line may grow before the next token is
/// folded onto a line of its own: below RFC 5322's 998, with room for `,`.
const FOLD_AT: usize = 900;

/// A complete `From`/`To`/`Cc` field, CRLF-terminated. Each piece is capped
/// on its own, but a name, an address and a sender-chosen number of
/// recipients still add up, so the LINE is what gets limited: a token that
/// would push it past [`FOLD_AT`] starts a folded line. A plain line thus
/// stays under 998 octets, and the only longer one is a lone base64
/// encoded-word, which has no `:` for a relay's split to turn into a field.
/// Ordinary mail fits on one line and renders exactly as unfolded.
fn address_field<'a>(name: &str, addrs: impl IntoIterator<Item = &'a MailAddress>) -> String {
    let mut field = format!("{name}:");
    let mut line_len = field.len();
    for (i, addr) in addrs.into_iter().enumerate() {
        if i > 0 {
            field.push(',');
            line_len += 1;
        }
        for token in header_address_tokens(addr) {
            if line_len + 1 + token.len() > FOLD_AT {
                field.push_str("\r\n");
                line_len = 0;
            }
            field.push(' ');
            field.push_str(&token);
            line_len += 1 + token.len();
        }
    }
    field.push_str("\r\n");
    field
}

/// `text` with every character outside printable ASCII replaced by `?`.
fn printable_ascii(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '?'
            }
        })
        .collect()
}

/// Longer values are base64-encoded: RFC 5322 caps a line at 998 octets, a
/// relay may split one that exceeds it, and base64 has no `:` for a split to
/// turn into a field of the sender's choosing.
const MAX_PLAIN_VALUE_LEN: usize = 900;

fn encoded_word(s: &str) -> String {
    format!(
        "=?UTF-8?B?{}?=",
        base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
    )
}

/// Line breaks are replaced BEFORE encoding: an encoded-word hides them on
/// the wire, but a client that decodes headers would get them back, and with
/// them whatever line the sender put after one. Text that already looks like
/// an encoded-word is wrapped in ours, so one decode yields it literally.
pub(crate) fn encode_header_value(s: &str) -> String {
    let s = sanitize_header_line(s);
    if s.is_ascii() && !s.contains(ENCODED_WORD_START) && s.len() <= MAX_PLAIN_VALUE_LEN {
        s
    } else {
        encoded_word(&s)
    }
}

pub(crate) fn format_rfc2822_date(millis: u64) -> String {
    let secs = millis / 1000;
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    let weekday = ((days + 4) % 7) as usize; // 0=Sun, epoch was Thursday
    let weekdays = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

    let (year, month, day) = days_to_ymd(days);
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    let month_idx = month.saturating_sub(1).min(11) as usize;

    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} +0000",
        weekdays[weekday], day, months[month_idx], year, hours, minutes, seconds
    )
}

/// Howard Hinnant's civil_from_days algorithm
/// Returns (year, month 1-12, day 1-31)
pub(crate) fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

pub(crate) fn format_internal_date(millis: u64) -> String {
    let secs = millis / 1000;
    let days = secs / 86400;
    let tod = secs % 86400;
    let h = tod / 3600;
    let m = (tod % 3600) / 60;
    let s = tod % 60;

    let (year, month, day) = days_to_ymd(days);
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    let month_idx = month.saturating_sub(1).min(11) as usize;

    format!(
        "{:02}-{}-{:04} {:02}:{:02}:{:02} +0000",
        day, months[month_idx], year, h, m, s
    )
}

pub(crate) fn base64_encode_body(data: &[u8]) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(data);
    encoded
        .as_bytes()
        .chunks(76)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\r\n")
}

pub(crate) fn extract_headers(rfc: &str) -> String {
    if let Some(pos) = rfc.find("\r\n\r\n") {
        format!("{}\r\n", &rfc[..pos + 2])
    } else {
        rfc.to_string()
    }
}

/// Strip HTML markup down to readable text for full-text indexing. Drops tags,
/// the contents of `<script>`/`<style>` blocks, and decodes the handful of
/// entities that actually show up in mail bodies, then collapses whitespace.
/// This is lossy by design — it only needs to be good enough that a body
/// search matches the words a human would see, not the markup around them.
pub(crate) fn strip_html(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut chars = html.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '<' {
            // Capture the tag name to detect script/style blocks we must skip
            // wholesale (their text content is not human-visible).
            let mut tag = String::new();
            for t in chars.clone().take(6) {
                if t == '>' || t.is_whitespace() {
                    break;
                }
                tag.push(t.to_ascii_lowercase());
            }
            let skip_block = matches!(tag.trim_start_matches('/'), "script" | "style");
            // Consume up to and including the closing '>'.
            for t in chars.by_ref() {
                if t == '>' {
                    break;
                }
            }
            if skip_block && !tag.starts_with('/') {
                // Swallow everything until the matching closing tag.
                let close = format!("</{tag}");
                let mut window = String::new();
                for t in chars.by_ref() {
                    window.push(t.to_ascii_lowercase());
                    if window.ends_with(&close) {
                        // Drop the rest of the closing tag.
                        for t2 in chars.by_ref() {
                            if t2 == '>' {
                                break;
                            }
                        }
                        break;
                    }
                }
            }
            out.push(' ');
        } else {
            out.push(c);
        }
    }
    let decoded = decode_entities(&out);
    decoded.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn decode_entities(s: &str) -> String {
    s.replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
}

/// Extract the readable body text from one of our own RFC 2822 messages, for
/// full-text indexing: locate the first `text/*` part, base64-decode it, and
/// strip HTML. Works for both the single-part and multipart layouts produced
/// by [`mail_to_rfc2822`]. Returns an empty string when no text part is found.
pub(crate) fn extract_body_text(rfc: &str) -> String {
    // Find the first textual MIME part.
    let lower = rfc.to_lowercase();
    let part_start = lower.find("text/html").or_else(|| lower.find("text/plain"));
    let Some(part_start) = part_start else {
        return String::new();
    };
    // Body begins after that part's header/body separator.
    let Some(sep) = rfc[part_start..].find("\r\n\r\n") else {
        return String::new();
    };
    let body_start = part_start + sep + 4;
    // Body ends at the next MIME boundary delimiter (multipart) or end of input.
    let body_end = rfc[body_start..]
        .find("\r\n--")
        .map(|i| body_start + i)
        .unwrap_or(rfc.len());
    let raw = &rfc[body_start..body_end];

    let stripped_b64: String = raw.split_whitespace().collect();
    match base64::engine::general_purpose::STANDARD.decode(stripped_b64) {
        Ok(bytes) => strip_html(&String::from_utf8_lossy(&bytes)),
        // Not base64 (shouldn't happen for our own messages) — treat as text.
        Err(_) => strip_html(raw),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_id(s: &str) -> tutasdk::GeneratedId {
        tutasdk::GeneratedId(s.to_string())
    }

    #[test]
    fn test_days_to_ymd_epoch() {
        assert_eq!(days_to_ymd(0), (1970, 1, 1));
    }

    #[test]
    fn strip_html_drops_tags_and_decodes_entities() {
        let html = "<p>Hello&nbsp;<b>World</b> &amp; goodbye</p>";
        assert_eq!(strip_html(html), "Hello World & goodbye");
    }

    #[test]
    fn strip_html_skips_script_and_style() {
        let html = "<style>.a{color:red}</style><div>Visible</div><script>alert(1)</script>";
        assert_eq!(strip_html(html), "Visible");
    }

    #[test]
    fn extract_body_text_from_single_part() {
        let body = base64::engine::general_purpose::STANDARD.encode("<p>Quarterly invoice</p>");
        let rfc = format!(
            "Subject: Test\r\nContent-Type: text/html; charset=UTF-8\r\n\
             Content-Transfer-Encoding: base64\r\n\r\n{body}\r\n"
        );
        assert_eq!(extract_body_text(&rfc), "Quarterly invoice");
    }

    #[test]
    fn extract_body_text_from_multipart_stops_at_boundary() {
        let body = base64::engine::general_purpose::STANDARD.encode("<p>Body words here</p>");
        let rfc = format!(
            "Content-Type: multipart/mixed; boundary=\"BND\"\r\n\r\n\
             --BND\r\nContent-Type: text/html; charset=UTF-8\r\n\
             Content-Transfer-Encoding: base64\r\n\r\n{body}\r\n\
             --BND\r\nContent-Type: application/pdf\r\n\r\nIGNOREDATTACHMENT\r\n--BND--\r\n"
        );
        assert_eq!(extract_body_text(&rfc), "Body words here");
    }

    #[test]
    fn test_days_to_ymd_known_dates() {
        // 2024-01-01 = day 19723 since epoch
        assert_eq!(days_to_ymd(19723), (2024, 1, 1));
        // 2000-02-29 (leap year) = day 11016
        assert_eq!(days_to_ymd(11016), (2000, 2, 29));
        // 2026-05-20 = day 20593
        assert_eq!(days_to_ymd(20593), (2026, 5, 20));
    }

    #[test]
    fn test_format_rfc2822_date_epoch() {
        let result = format_rfc2822_date(0);
        assert_eq!(result, "Thu, 01 Jan 1970 00:00:00 +0000");
    }

    #[test]
    fn test_format_rfc2822_date_known() {
        // 2024-12-25 12:37:25 UTC = 1735130245000 ms
        let result = format_rfc2822_date(1735130245000);
        assert_eq!(result, "Wed, 25 Dec 2024 12:37:25 +0000");
    }

    #[test]
    fn test_format_internal_date_epoch() {
        let result = format_internal_date(0);
        assert_eq!(result, "01-Jan-1970 00:00:00 +0000");
    }

    #[test]
    fn test_format_internal_date_known() {
        let result = format_internal_date(1735130245000);
        assert_eq!(result, "25-Dec-2024 12:37:25 +0000");
    }

    #[test]
    fn test_encode_header_ascii() {
        assert_eq!(encode_header_value("Hello World"), "Hello World");
    }

    #[test]
    fn test_encode_header_utf8() {
        let result = encode_header_value("Héllo Wörld");
        assert!(result.starts_with("=?UTF-8?B?"));
        assert!(result.ends_with("?="));

        // Decode to verify round-trip
        let b64_part = &result[10..result.len() - 2];
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(b64_part)
            .unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "Héllo Wörld");
    }

    #[test]
    fn test_encode_header_with_newline() {
        assert_eq!(encode_header_value("Line1\r\nLine2"), "Line1  Line2");
    }

    #[test]
    fn test_encode_header_empty() {
        assert_eq!(encode_header_value(""), "");
    }

    #[test]
    fn test_format_address_name_and_email() {
        let addr = MailAddress {
            _id: None,
            name: "John Doe".to_string(),
            address: "john@example.com".to_string(),
            contact: None,
            _errors: Default::default(),
        };
        assert_eq!(format_address(&addr), "John Doe <john@example.com>");
    }

    #[test]
    fn test_format_address_email_only() {
        let addr = MailAddress {
            _id: None,
            name: "".to_string(),
            address: "john@example.com".to_string(),
            contact: None,
            _errors: Default::default(),
        };
        assert_eq!(format_address(&addr), "john@example.com");
    }

    #[test]
    fn test_format_address_utf8_name() {
        let addr = MailAddress {
            _id: None,
            name: "Jéan-François".to_string(),
            address: "jf@example.com".to_string(),
            contact: None,
            _errors: Default::default(),
        };
        let result = format_address(&addr);
        assert!(result.contains("=?UTF-8?B?"));
        assert!(result.ends_with(" <jf@example.com>"));
    }

    #[test]
    fn test_base64_encode_body_short() {
        let result = base64_encode_body(b"Hello");
        assert_eq!(result, "SGVsbG8=");
    }

    #[test]
    fn test_base64_encode_body_long_wraps() {
        let long_text = "A".repeat(200);
        let result = base64_encode_body(long_text.as_bytes());
        for line in result.split("\r\n") {
            assert!(line.len() <= 76, "Line too long: {} chars", line.len());
        }
    }

    #[test]
    fn test_base64_encode_body_empty() {
        assert_eq!(base64_encode_body(b""), "");
    }

    #[test]
    fn passthrough_keeps_provenance_headers() {
        let raw = "From: a@b.com\r\nList-Unsubscribe: <https://x.test/u?id=1>\r\n\
                   Precedence: bulk\r\nAuto-Submitted: auto-generated\r\n";
        assert_eq!(
            passthrough_headers(raw),
            vec![
                "List-Unsubscribe: <https://x.test/u?id=1>",
                "Precedence: bulk",
                "Auto-Submitted: auto-generated",
            ]
        );
    }

    #[test]
    fn passthrough_drops_structural_headers() {
        let raw = "Content-Type: text/plain; boundary=\"old\"\r\n\
                   Message-ID: <original@sender.test>\r\n\
                   DKIM-Signature: v=1; a=rsa-sha256; b=abc\r\n\
                   Received: from mx.test by y.test\r\n\
                   MIME-Version: 1.0\r\n\
                   Content-Transfer-Encoding: quoted-printable\r\n";
        assert!(passthrough_headers(raw).is_empty());
    }

    #[test]
    fn passthrough_preserves_folded_values() {
        let raw = "List-Unsubscribe: <https://x.test/u?id=1>,\r\n\t<mailto:u@x.test>\r\n";
        assert_eq!(
            passthrough_headers(raw),
            vec!["List-Unsubscribe: <https://x.test/u?id=1>,\r\n\t<mailto:u@x.test>"]
        );
    }

    #[test]
    fn passthrough_is_case_insensitive_on_field_names() {
        let raw = "list-unsubscribe: <https://x.test/u>\r\nLIST-ID: <news.x.test>\r\n";
        assert_eq!(passthrough_headers(raw).len(), 2);
    }

    #[test]
    fn passthrough_cannot_smuggle_a_structural_header() {
        // A sender-controlled value that tries to inject a header of its own:
        // in the block that is simply a second, non-allowlisted field line.
        let raw = "List-Id: <news.x.test>\r\nContent-Type: text/evil\r\n";
        assert_eq!(passthrough_headers(raw), vec!["List-Id: <news.x.test>"]);
    }

    #[test]
    fn passthrough_stops_at_the_end_of_the_header_block() {
        let raw = "List-Id: <news.x.test>\r\n\r\nPrecedence: bulk in the body\r\n";
        assert_eq!(passthrough_headers(raw), vec!["List-Id: <news.x.test>"]);
    }

    #[test]
    fn passthrough_on_mail_without_original_headers_is_empty() {
        assert!(passthrough_headers("").is_empty());
    }

    #[test]
    fn field_names_lists_names_without_values() {
        let raw =
            "From: a@b.com\r\nList-Unsubscribe: <https://x.test/u>,\r\n\t<mailto:u@x.test>\r\n";
        assert_eq!(field_names(raw), vec!["From", "List-Unsubscribe"]);
    }

    #[test]
    fn test_extract_headers_normal() {
        let rfc = "From: a@b.com\r\nTo: c@d.com\r\n\r\nBody here";
        let headers = extract_headers(rfc);
        // extract_headers includes the trailing \r\n\r\n separator
        assert_eq!(headers, "From: a@b.com\r\nTo: c@d.com\r\n\r\n");
        assert!(!headers.contains("Body"));
    }

    #[test]
    fn test_extract_headers_no_body() {
        let rfc = "From: a@b.com\r\nTo: c@d.com";
        let headers = extract_headers(rfc);
        assert_eq!(headers, rfc);
    }

    #[test]
    fn test_mail_to_rfc2822_minimal() {
        use tutasdk::date::DateTime;
        use tutasdk::IdTupleGenerated;

        let mail = Mail {
            _id: Some(IdTupleGenerated::new(test_id("list1"), test_id("elem1"))),
            _permissions: test_id("perm1"),
            _format: 0,
            _ownerEncSessionKey: None,
            subject: "Test Subject".to_string(),
            receivedDate: DateTime::from_millis(1735130245000),
            state: 2,
            unread: false,
            confidential: false,
            replyType: 0,
            _ownerGroup: None,
            differentEnvelopeSender: None,
            listUnsubscribe: false,
            movedTime: None,
            phishingStatus: 0,
            authStatus: None,
            method: 0,
            recipientCount: 1,
            encryptionAuthStatus: None,
            _ownerKeyVersion: None,
            processingState: 0,
            processNeeded: false,
            sendAt: None,
            serverClassificationData: None,
            _kdfNonce: None,
            sender: MailAddress {
                _id: None,
                name: "Alice".to_string(),
                address: "alice@tuta.com".to_string(),
                contact: None,
                _errors: Default::default(),
            },
            attachments: vec![],
            conversationEntry: IdTupleGenerated::new(test_id("conv_list1"), test_id("conv_elem1")),
            firstRecipient: Some(MailAddress {
                _id: None,
                name: "Bob".to_string(),
                address: "bob@example.com".to_string(),
                contact: None,
                _errors: Default::default(),
            }),
            mailDetails: None,
            mailDetailsDraft: None,
            bucketKey: None,
            sets: vec![],
            clientSpamClassifierResult: None,
            _errors: Default::default(),
        };

        let rfc = mail_to_rfc2822(&mail, None, &[]);

        assert!(rfc.contains("Date: Wed, 25 Dec 2024 12:37:25 +0000\r\n"));
        assert!(rfc.contains("From: Alice <alice@tuta.com>\r\n"));
        assert!(rfc.contains("Subject: Test Subject\r\n"));
        assert!(rfc.contains("To: Bob <bob@example.com>\r\n"));
        assert!(rfc.contains("MIME-Version: 1.0\r\n"));
        assert!(rfc.contains("Content-Type: text/html; charset=UTF-8\r\n"));
        assert!(rfc.contains("Content-Transfer-Encoding: base64\r\n"));
        assert!(rfc.contains("Message-ID: <"));
        // Body should be base64 of "<p>(No body available)</p>"
        assert!(rfc.contains("\r\n\r\n"));
    }

    #[test]
    fn test_mail_to_rfc2822_with_details() {
        use tutasdk::date::DateTime;
        use tutasdk::entities::generated::tutanota::{Body, Header, Recipients};
        use tutasdk::IdTupleGenerated;

        let mail = Mail {
            _id: Some(IdTupleGenerated::new(test_id("list2"), test_id("elem2"))),
            _permissions: test_id("perm2"),
            _format: 0,
            _ownerEncSessionKey: None,
            subject: "With Details".to_string(),
            receivedDate: DateTime::from_millis(0),
            state: 2,
            unread: true,
            confidential: false,
            replyType: 0,
            _ownerGroup: None,
            differentEnvelopeSender: None,
            listUnsubscribe: false,
            movedTime: None,
            phishingStatus: 0,
            authStatus: None,
            method: 0,
            recipientCount: 2,
            encryptionAuthStatus: None,
            _ownerKeyVersion: None,
            processingState: 0,
            processNeeded: false,
            sendAt: None,
            serverClassificationData: None,
            _kdfNonce: None,
            sender: MailAddress {
                _id: None,
                name: "".to_string(),
                address: "sender@tuta.com".to_string(),
                contact: None,
                _errors: Default::default(),
            },
            attachments: vec![],
            conversationEntry: IdTupleGenerated::new(test_id("conv_list2"), test_id("conv_elem2")),
            firstRecipient: None,
            mailDetails: None,
            mailDetailsDraft: None,
            bucketKey: None,
            sets: vec![],
            clientSpamClassifierResult: None,
            _errors: Default::default(),
        };

        let details = MailDetails {
            _id: None,
            sentDate: DateTime::from_millis(0),
            authStatus: 0,
            replyTos: vec![],
            recipients: Recipients {
                _id: None,
                toRecipients: vec![
                    MailAddress {
                        _id: None,
                        name: "Bob".to_string(),
                        address: "bob@example.com".to_string(),
                        contact: None,
                        _errors: Default::default(),
                    },
                    MailAddress {
                        _id: None,
                        name: "".to_string(),
                        address: "charlie@example.com".to_string(),
                        contact: None,
                        _errors: Default::default(),
                    },
                ],
                ccRecipients: vec![MailAddress {
                    _id: None,
                    name: "Dave".to_string(),
                    address: "dave@example.com".to_string(),
                    contact: None,
                    _errors: Default::default(),
                }],
                bccRecipients: vec![],
            },
            headers: Some(Header {
                _id: None,
                headers: Some(
                    "Message-ID: <original@sender.test>\r\n\
                     Content-Type: text/plain; boundary=\"stale\"\r\n\
                     List-Unsubscribe: <https://x.test/u?id=1>\r\n\
                     Precedence: bulk\r\n"
                        .to_string(),
                ),
                compressedHeaders: None,
                _errors: Default::default(),
            }),
            body: Body {
                _id: None,
                text: Some("<p>Hello World</p>".to_string()),
                compressedText: None,
                _errors: Default::default(),
            },
        };

        let rfc = mail_to_rfc2822(&mail, Some(&details), &[]);

        assert!(rfc.contains("From: sender@tuta.com\r\n"));
        assert!(rfc.contains("To: Bob <bob@example.com>, charlie@example.com\r\n"));
        assert!(rfc.contains("Cc: Dave <dave@example.com>\r\n"));
        // Provenance headers ride along; structural ones from the original
        // never do — the body below is ours, not the sender's.
        assert!(rfc.contains("List-Unsubscribe: <https://x.test/u?id=1>\r\n"));
        assert!(rfc.contains("Precedence: bulk\r\n"));
        assert!(!rfc.contains("original@sender.test"));
        assert!(!rfc.contains("stale"));
        assert_eq!(rfc.matches("Message-ID:").count(), 1);
        assert_eq!(rfc.matches("Content-Type:").count(), 1);
        // Body should be base64 of "<p>Hello World</p>"
        let body_b64 = base64::engine::general_purpose::STANDARD.encode(b"<p>Hello World</p>");
        assert!(rfc.contains(&body_b64));
    }

    #[test]
    fn test_mail_to_rfc2822_with_attachment_emits_multipart() {
        use tutasdk::date::DateTime;
        use tutasdk::entities::generated::tutanota::{Body, Recipients, TutanotaFile};
        use tutasdk::IdTupleGenerated;

        let mail = Mail {
            _id: Some(IdTupleGenerated::new(
                test_id("list_att"),
                test_id("elem_att"),
            )),
            _permissions: test_id("perm_att"),
            _format: 0,
            _ownerEncSessionKey: None,
            subject: "With Attachment".to_string(),
            receivedDate: DateTime::from_millis(0),
            state: 2,
            unread: false,
            confidential: false,
            replyType: 0,
            _ownerGroup: None,
            differentEnvelopeSender: None,
            listUnsubscribe: false,
            movedTime: None,
            phishingStatus: 0,
            authStatus: None,
            method: 0,
            recipientCount: 1,
            encryptionAuthStatus: None,
            _ownerKeyVersion: None,
            processingState: 0,
            processNeeded: false,
            sendAt: None,
            serverClassificationData: None,
            _kdfNonce: None,
            sender: MailAddress {
                _id: None,
                name: "Alice".to_string(),
                address: "alice@tuta.com".to_string(),
                contact: None,
                _errors: Default::default(),
            },
            attachments: vec![],
            conversationEntry: IdTupleGenerated::new(test_id("conv_l"), test_id("conv_e")),
            firstRecipient: Some(MailAddress {
                _id: None,
                name: "".to_string(),
                address: "bob@example.com".to_string(),
                contact: None,
                _errors: Default::default(),
            }),
            mailDetails: None,
            mailDetailsDraft: None,
            bucketKey: None,
            sets: vec![],
            clientSpamClassifierResult: None,
            _errors: Default::default(),
        };
        let details = MailDetails {
            _id: None,
            sentDate: DateTime::from_millis(0),
            authStatus: 0,
            replyTos: vec![],
            recipients: Recipients {
                _id: None,
                toRecipients: vec![],
                ccRecipients: vec![],
                bccRecipients: vec![],
            },
            headers: None,
            body: Body {
                _id: None,
                text: Some("<p>The body</p>".to_string()),
                compressedText: None,
                _errors: Default::default(),
            },
        };
        let file = TutanotaFile {
            _id: Some(IdTupleGenerated::new(
                test_id("file_list"),
                test_id("file_elem"),
            )),
            _permissions: test_id("file_perm"),
            _format: 0,
            _ownerEncSessionKey: None,
            name: "doc.pdf".to_string(),
            size: 5,
            mimeType: Some("application/pdf".to_string()),
            _ownerGroup: None,
            cid: None,
            _ownerKeyVersion: None,
            _kdfNonce: None,
            parent: None,
            subFiles: None,
            blobs: vec![],
            _errors: Default::default(),
        };
        let data: &[u8] = b"PDFDA";
        let attachments: Vec<super::AttachmentPart> = vec![(&file, data)];
        let rfc = mail_to_rfc2822(&mail, Some(&details), &attachments);

        assert!(rfc.contains(
            "Content-Type: multipart/mixed; boundary=\"=_TutaBridge_list_att_elem_att\""
        ));
        assert!(rfc.contains("--=_TutaBridge_list_att_elem_att\r\n"));
        // Body part: text/html base64
        assert!(rfc.contains("Content-Type: text/html; charset=UTF-8\r\n"));
        let body_b64 = base64::engine::general_purpose::STANDARD.encode(b"<p>The body</p>");
        assert!(rfc.contains(&body_b64));
        // Attachment part
        assert!(rfc.contains("Content-Type: application/pdf; name=\"doc.pdf\""));
        assert!(rfc.contains("Content-Disposition: attachment; filename=\"doc.pdf\""));
        let pdf_b64 = base64::engine::general_purpose::STANDARD.encode(data);
        assert!(rfc.contains(&pdf_b64));
        // Closing boundary
        assert!(rfc.ends_with("--=_TutaBridge_list_att_elem_att--\r\n"));
    }

    // --- X-Tutabridge-Authentication ---

    fn auth_mail(sender_address: &str) -> Mail {
        use tutasdk::date::DateTime;
        use tutasdk::IdTupleGenerated;

        Mail {
            _id: Some(IdTupleGenerated::new(
                test_id("auth_list"),
                test_id("auth_elem"),
            )),
            _permissions: test_id("perm"),
            _format: 0,
            _ownerEncSessionKey: None,
            subject: "Auth".to_string(),
            receivedDate: DateTime::from_millis(0),
            state: 2,
            unread: true,
            confidential: false,
            replyType: 0,
            _ownerGroup: None,
            differentEnvelopeSender: None,
            listUnsubscribe: false,
            movedTime: None,
            phishingStatus: 0,
            authStatus: None,
            method: 0,
            recipientCount: 1,
            encryptionAuthStatus: None,
            _ownerKeyVersion: None,
            processingState: 0,
            processNeeded: false,
            sendAt: None,
            serverClassificationData: None,
            _kdfNonce: None,
            sender: MailAddress {
                _id: None,
                name: "".to_string(),
                address: sender_address.to_string(),
                contact: None,
                _errors: Default::default(),
            },
            attachments: vec![],
            conversationEntry: IdTupleGenerated::new(test_id("conv_l"), test_id("conv_e")),
            firstRecipient: None,
            mailDetails: None,
            mailDetailsDraft: None,
            bucketKey: None,
            sets: vec![],
            clientSpamClassifierResult: None,
            _errors: Default::default(),
        }
    }

    fn auth_details(auth_status: i64, original_headers: &str) -> MailDetails {
        use tutasdk::date::DateTime;
        use tutasdk::entities::generated::tutanota::{Body, Header, Recipients};

        MailDetails {
            _id: None,
            sentDate: DateTime::from_millis(0),
            authStatus: auth_status,
            replyTos: vec![],
            recipients: Recipients {
                _id: None,
                toRecipients: vec![],
                ccRecipients: vec![],
                bccRecipients: vec![],
            },
            headers: Some(Header {
                _id: None,
                headers: Some(original_headers.to_string()),
                compressedHeaders: None,
                _errors: Default::default(),
            }),
            body: Body {
                _id: None,
                text: Some(format!(
                    "<p>{AUTHENTICATION_HEADER}: status=authenticated in the body</p>"
                )),
                compressedText: None,
                _errors: Default::default(),
            },
        }
    }

    /// Every line of the served header block that a lenient reader could
    /// take for a field named like ours: any of CR, LF or CRLF is a line
    /// break, and a line counts when its Unicode-uppercased text merely
    /// STARTS with the name — no colon or exact-name rule, so lookalike and
    /// fold-before-colon forms are counted too. Kept independent of
    /// `opens_authentication_field` so it does not share its blind spots.
    fn authentication_fields(rfc: &str) -> Vec<&str> {
        let ours = AUTHENTICATION_HEADER.to_uppercase();
        let head = rfc.split("\r\n\r\n").next().unwrap();
        // Python's `str.splitlines` set, spelled out independently.
        head.split([
            '\n', '\x0b', '\x0c', '\r', '\x1c', '\x1d', '\x1e', '\u{85}', '\u{2028}', '\u{2029}',
        ])
        .filter(|line| line.trim_start().to_uppercase().starts_with(&ours))
        .collect()
    }

    #[test]
    fn a_drafts_bcc_survives_the_rendition() {
        let mut details = auth_details(0, "");
        details.recipients.bccRecipients = vec![MailAddress {
            _id: None,
            name: String::new(),
            address: "hidden@x.test".to_string(),
            contact: None,
            _errors: Default::default(),
        }];
        let rfc = mail_to_rfc2822(&auth_mail("me@x.test"), Some(&details), &[]);
        assert!(rfc.contains("\r\nBcc: hidden@x.test\r\n"), "{rfc:?}");
    }

    #[test]
    fn authentication_header_is_first_and_carries_the_details_verdict() {
        let rfc = mail_to_rfc2822(&auth_mail("a@x.test"), Some(&auth_details(1, "")), &[]);
        assert!(rfc.starts_with(
            "X-Tutabridge-Authentication: status=hard_fail; status-source=tuta-server; \
             encryption-auth=unknown; encryption-auth-source=tuta-client-decrypt; v=1\r\n"
        ));
    }

    #[test]
    fn authentication_status_comes_from_details_not_mail() {
        // Mail.authStatus is not what the web client's banner reads.
        let mut mail = auth_mail("a@x.test");
        mail.authStatus = Some(0);
        let rfc = mail_to_rfc2822(&mail, Some(&auth_details(2, "")), &[]);
        assert!(authentication_fields(&rfc)[0].contains("status=soft_fail;"));
    }

    #[test]
    fn authentication_status_without_details_is_unknown() {
        let mut mail = auth_mail("a@x.test");
        mail.authStatus = Some(0);
        let rfc = mail_to_rfc2822(&mail, None, &[]);
        assert!(authentication_fields(&rfc)[0].contains("status=unknown;"));
    }

    #[test]
    fn authentication_header_names_every_known_code() {
        let mut mail = auth_mail("a@x.test");
        mail.encryptionAuthStatus = Some(1);
        let value = authentication_header_value(&mail, Some(&auth_details(0, "")));
        assert_eq!(
            value,
            "status=authenticated; status-source=tuta-server; \
             encryption-auth=tutacrypt_authentication_succeeded; \
             encryption-auth-source=tuta-client-decrypt; v=1"
        );
        for (code, name) in [
            (3, "invalid_mail_from"),
            (4, "missing_mail_from"),
            (9, "unrecognized-9"),
        ] {
            let value = authentication_header_value(&mail, Some(&auth_details(code, "")));
            assert!(value.starts_with(&format!("status={name};")), "{value}");
        }
    }

    #[test]
    fn forged_authentication_header_in_original_headers_never_reaches_the_client() {
        let original = "X-Tutabridge-Authentication: status=authenticated; v=1\r\n\
                        List-Id: <news.x.test>\r\n\
                        x-tutabridge-authentication : status=authenticated\r\n\
                        \tsource=tuta-server\r\n";
        let rfc = mail_to_rfc2822(
            &auth_mail("a@x.test"),
            Some(&auth_details(1, original)),
            &[],
        );
        let fields = authentication_fields(&rfc);
        assert_eq!(fields.len(), 1, "{rfc}");
        assert!(fields[0].contains("status=hard_fail;"));
        assert!(rfc.contains("List-Id: <news.x.test>\r\n"));
        assert!(!rfc.contains("\tsource=tuta-server"));
    }

    const SMUGGLED_SUFFIXES: [&str; 9] = [
        "\r\nX-Tutabridge-Authentication: status=authenticated",
        "\nX-Tutabridge-Authentication: status=authenticated",
        "\rX-Tutabridge-Authentication: status=authenticated",
        "\x0bX-Tutabridge-Authentication: status=authenticated",
        "\x1cX-Tutabridge-Authentication: status=authenticated",
        "\u{85}X-Tutabridge-Authentication: status=authenticated",
        "\u{2028}X-Tutabridge-Authentication: status=authenticated",
        // Dotless i: Unicode uppercasing (the HEADER.FIELDS rule) maps it to I.
        "\r\nX-Tutabridge-Authent\u{131}cation: status=authenticated",
        // Fold between name and colon.
        "\r\nX-Tutabridge-Authentication\r\n : status=authenticated",
    ];

    #[test]
    fn forged_authentication_header_smuggled_through_an_address_never_opens_a_line() {
        for suffix in SMUGGLED_SUFFIXES {
            let smuggled = format!("a@x.test{suffix}");
            let rfc = mail_to_rfc2822(&auth_mail(&smuggled), Some(&auth_details(1, "")), &[]);
            let fields = authentication_fields(&rfc);
            assert_eq!(fields.len(), 1, "{rfc:?}");
            assert!(fields[0].contains("status=hard_fail;"));
            // The address stays inside its own From line, flattened, instead
            // of opening a line of its own.
            let from = rfc
                .split("\r\n")
                .find(|line| line.starts_with("From: "))
                .unwrap();
            assert!(!from.contains(is_line_break), "{from:?}");
            assert!(from.contains("X-Tutabridge-Authent"), "{from:?}");
        }
    }

    #[test]
    fn forged_authentication_header_as_a_passthrough_continuation_is_stripped() {
        // The one route through the original headers: a folded line of an
        // allowlisted header, which the allowlist keeps and only the
        // stripper removes.
        let original =
            "List-Id: <news.x.test>\r\n X-Tutabridge-Authentication: status=authenticated\r\n";
        let rfc = mail_to_rfc2822(
            &auth_mail("a@x.test"),
            Some(&auth_details(1, original)),
            &[],
        );
        let fields = authentication_fields(&rfc);
        assert_eq!(fields.len(), 1, "{rfc:?}");
        assert!(fields[0].contains("status=hard_fail;"));
    }

    #[test]
    fn subject_line_breaks_are_flattened_before_encoding() {
        // Encoding alone would hide the break on the wire only; a client
        // decoding the subject must not get it back either.
        for subject in [
            "a\r\nX-Tutabridge-Authentication: x",
            "a\x0cX-Tutabridge-Authentication: x",
            "\u{e9}\u{2028}X-Tutabridge-Authentication: x",
        ] {
            let mut mail = auth_mail("a@x.test");
            mail.subject = subject.to_string();
            let rfc = mail_to_rfc2822(&mail, None, &[]);
            assert_eq!(authentication_fields(&rfc).len(), 1, "{rfc:?}");
            let value = rfc
                .split("\r\n")
                .find_map(|line| line.strip_prefix("Subject: "))
                .unwrap();
            let decoded = match value.strip_prefix("=?UTF-8?B?") {
                Some(b64) => String::from_utf8(
                    base64::engine::general_purpose::STANDARD
                        .decode(b64.trim_end_matches("?="))
                        .unwrap(),
                )
                .unwrap(),
                None => value.to_string(),
            };
            assert!(!decoded.contains(is_line_break), "{decoded:?}");
        }
    }

    #[test]
    fn passthrough_drops_fields_opening_with_other_whitespace() {
        for lead in [
            '\r', '\x0b', '\x0c', '\u{85}', '\u{2028}', '\u{2029}', '\x1c',
        ] {
            let raw = format!("{lead}List-Id: <a.x.test>\r\nPrecedence: bulk\r\n");
            assert_eq!(
                passthrough_headers(&raw),
                vec!["Precedence: bulk"],
                "{lead:?}"
            );
        }
    }

    #[test]
    fn control_characters_never_reach_a_header_line() {
        let raw = "List-Id: <ok>\r\n \x1fX-Tutabridge-Authentication: status=authenticated\r\n";
        let rfc = mail_to_rfc2822(
            &auth_mail("a\x00b@x.test"),
            Some(&auth_details(1, raw)),
            &[],
        );
        let head = rfc.split("\r\n\r\n").next().unwrap();
        assert!(
            !head
                .chars()
                .any(|c| c.is_control() && !matches!(c, '\r' | '\n')),
            "{head:?}"
        );
        // A reader trimming each line without unfolding sees one copy.
        let copies = head
            .split("\r\n")
            .filter(|line| {
                line.trim_matches(|c: char| c.is_whitespace() || c.is_control())
                    .to_uppercase()
                    .starts_with(&AUTHENTICATION_HEADER.to_uppercase())
            })
            .count();
        assert_eq!(copies, 1, "{head:?}");
    }

    #[test]
    fn every_top_level_header_line_is_plain_ascii() {
        // UTF-8 `Å` is C3 85: through Latin-1 its 0x85 is NEL, a line break.
        let raw = "List-Id: <l.x> a\u{c5}X-Tutabridge-Authentication: status=authenticated\r\n\
                   List-Unsubscribe: <https://x.test/u>,\r\n \u{feff}X-Tutabridge-Authentication: y\r\n\
                   Precedence: bulk\r\n";
        let mut mail = auth_mail("a\u{c5}X-Tutabridge-Authentication@x.test");
        mail.sender.name = "\u{c5}sa\u{feff}".to_string();
        mail.subject = "caf\u{e9}\u{feff}".to_string();
        let rfc = mail_to_rfc2822(&mail, Some(&auth_details(1, raw)), &[]);
        let head = rfc.split("\r\n\r\n").next().unwrap();
        assert!(is_plain_header_text(head), "{head:?}");
        assert!(
            head.contains("<a?X-Tutabridge-Authentication@x.test>"),
            "{head:?}"
        );
        assert!(head.contains("\r\nPrecedence: bulk"), "{head:?}");
        assert!(!head.contains("List-Id") && !head.contains("List-Unsubscribe"));
    }

    fn sample_file() -> TutanotaFile {
        use tutasdk::IdTupleGenerated;
        TutanotaFile {
            _id: Some(IdTupleGenerated::new(test_id("fl"), test_id("fe"))),
            _permissions: test_id("fp"),
            _format: 0,
            _ownerEncSessionKey: None,
            name: "a.txt".to_string(),
            size: 1,
            mimeType: Some("text/plain".to_string()),
            _ownerGroup: None,
            cid: None,
            _ownerKeyVersion: None,
            _kdfNonce: None,
            parent: None,
            subFiles: None,
            blobs: vec![],
            _errors: Default::default(),
        }
    }

    #[test]
    fn server_ids_are_held_to_printable_ascii_too() {
        use tutasdk::IdTupleGenerated;
        let mut mail = auth_mail("a@x.test");
        mail._id = Some(IdTupleGenerated::new(
            test_id("L\u{85}\u{feff}"),
            test_id("E\u{e9}"),
        ));
        let att_file = sample_file();
        let rfc = mail_to_rfc2822(&mail, None, &[(&att_file, b"x".as_slice())]);
        let head = rfc.split("\r\n\r\n").next().unwrap();
        assert!(is_plain_header_text(head), "{head:?}");
        assert!(
            head.contains("Message-ID: <L??.E?@tutabridge.local>"),
            "{head:?}"
        );
    }

    #[test]
    fn over_long_values_never_produce_an_over_long_plain_line() {
        let forged = "X-Tutabridge-Authentication: status=authenticated";
        let mut mail = auth_mail(&format!("{}{forged}@x.test", "a".repeat(300)));
        mail.subject = format!("{}{forged}", "s".repeat(1000));
        let raw = format!(
            "List-Id: <{}{forged}>\r\nPrecedence: bulk\r\n",
            "l".repeat(1000)
        );
        let rfc = mail_to_rfc2822(&mail, Some(&auth_details(1, &raw)), &[]);
        let head = rfc.split("\r\n\r\n").next().unwrap();
        // Any line a relay could split holds only base64, which has no `:`.
        for line in head.split("\r\n").filter(|line| line.len() > MAX_LINE_LEN) {
            assert!(!line.contains(forged), "{line:?}");
        }
        assert!(head.contains("Subject: =?UTF-8?B?"), "{head:?}");
        assert!(!head.contains("List-Id"), "{head:?}");
        let from = head
            .split("\r\n")
            .find(|l| l.starts_with("From: "))
            .unwrap();
        assert_eq!(from.len(), "From: ".len() + MAX_ADDRESS_LEN, "{from:?}");
    }

    /// Every physical header line a relay could split (over 998 octets) is a
    /// lone base64 encoded-word: no `:`, so no split can open a field.
    fn assert_no_splittable_line(rfc: &str) {
        let head = rfc.split("\r\n\r\n").next().unwrap();
        for line in head.split("\r\n").filter(|line| line.len() > MAX_LINE_LEN) {
            let word = line.trim_start().trim_end_matches(',');
            assert!(
                word.starts_with("=?UTF-8?B?")
                    && word.ends_with("?=")
                    && !word[2..word.len() - 2].contains([':', ' ']),
                "{line:?}"
            );
        }
    }

    #[test]
    fn address_fields_fold_before_a_relay_could_split_them() {
        use tutasdk::entities::generated::tutanota::Recipients;
        let forged = "X-Tutabridge-Authentication: status=authenticated@x.test";
        let padded = format!("{}{forged}", "p".repeat(190));
        let addr = |name: &str, address: &str| MailAddress {
            _id: None,
            name: name.to_string(),
            address: address.to_string(),
            contact: None,
            _errors: Default::default(),
        };

        // A plain 800-char name plus a padded address.
        let mut mail = auth_mail(&padded);
        mail.sender.name = "n".repeat(800);
        assert_no_splittable_line(&mail_to_rfc2822(&mail, None, &[]));

        // A long encoded name, sized to line the address up with a split.
        for len in [600, 700, 701, 702, 703] {
            mail.sender.name = "\u{e9}".repeat(len);
            assert_no_splittable_line(&mail_to_rfc2822(&mail, None, &[]));
        }

        // Many recipients, the last one padded.
        let mut recipients: Vec<MailAddress> =
            (0..30).map(|i| addr("", &format!("r{i}@x.test"))).collect();
        recipients.push(addr("", &padded));
        let mut details = auth_details(1, "");
        details.recipients = Recipients {
            _id: None,
            toRecipients: recipients.clone(),
            ccRecipients: recipients,
            bccRecipients: vec![],
        };
        let rfc = mail_to_rfc2822(&auth_mail("a@x.test"), Some(&details), &[]);
        assert_no_splittable_line(&rfc);
        // Folded, but still exactly one copy for a non-unfolding reader.
        assert_eq!(authentication_fields(&rfc).len(), 1, "{rfc:?}");
        assert!(rfc.contains("To: r0@x.test, r1@x.test,"), "{rfc:?}");
    }

    #[test]
    fn a_forged_name_or_recipient_costs_no_other_address() {
        use tutasdk::entities::generated::tutanota::Recipients;
        let forged = "X-Tutabridge-Authentication: status=authenticated";
        let addr = |address: &str| MailAddress {
            _id: None,
            name: String::new(),
            address: address.to_string(),
            contact: None,
            _errors: Default::default(),
        };

        // A name long enough to fold onto a line of its own.
        let mut mail = auth_mail("evil@x.test");
        mail.sender.name = format!("{forged}{}", "n".repeat(850));
        let rfc = mail_to_rfc2822(&mail, None, &[]);
        assert!(rfc.contains("<evil@x.test>"), "{rfc:?}");
        let name = &mail.sender.name;
        assert!(
            rfc.contains(name.as_str()) || rfc.contains(&encoded_word(name)),
            "the name was stripped: {rfc:?}"
        );
        assert_eq!(authentication_fields(&rfc).len(), 1, "{rfc:?}");

        // A recipient whose bare address folds to the start of a line. The
        // padding varies so that, for some length, it lands exactly there.
        let mut hit_line_start = false;
        for pad in 0..40 {
            let mut to: Vec<MailAddress> = (0..33)
                .map(|i| addr(&format!("user{i:02}{}@x.test", "u".repeat(pad))))
                .collect();
            to.push(addr(
                "X-Tutabridge-Authentication:status=authenticated@x.test",
            ));
            to.extend((34..40).map(|i| addr(&format!("user{i:02}@x.test"))));
            let mut details = auth_details(1, "");
            details.recipients = Recipients {
                _id: None,
                toRecipients: to,
                ccRecipients: vec![],
                bccRecipients: vec![],
            };
            let rfc = mail_to_rfc2822(&auth_mail("a@x.test"), Some(&details), &[]);
            assert_eq!(authentication_fields(&rfc).len(), 1, "{rfc:?}");
            hit_line_start |= rfc.contains("\r\n <X-Tutabridge-Authentication:status");
            assert!(
                rfc.contains("status=authenticated@x.test>"),
                "{pad}: {rfc:?}"
            );
            for i in 34..40 {
                assert!(
                    rfc.contains(&format!("user{i:02}@x.test")),
                    "{pad} {i}: {rfc:?}"
                );
            }
        }
        assert!(
            hit_line_start,
            "no padding folded the forged recipient to a line start"
        );
    }

    #[test]
    fn stripper_drops_a_matching_continuation_line_alone() {
        let message = "To: a@x.test,\r\n X-Tutabridge-Authentication: forged,\r\n b@x.test\r\n\
                       Subject: s\r\n\r\n";
        assert_eq!(
            prepend_authentication_header(message, "status=unknown"),
            "X-Tutabridge-Authentication: status=unknown\r\n\
             To: a@x.test,\r\n b@x.test\r\nSubject: s\r\n\r\n"
        );
    }

    #[test]
    fn boundary_is_held_to_base64ext_and_70_chars() {
        use tutasdk::IdTupleGenerated;
        let mut mail = auth_mail("a@x.test");
        mail._id = Some(IdTupleGenerated::new(
            test_id("a b\"c;<>"),
            test_id(&"d\u{e9}e".repeat(40)),
        ));
        let boundary = build_boundary(&mail);
        assert!(boundary.len() <= 70, "{boundary:?}");
        assert!(
            boundary[2..]
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_')),
            "{boundary:?}"
        );
    }

    #[test]
    fn plain_ascii_addresses_render_unchanged() {
        for address in ["\"john doe\"@x.test", "o'brien+tag@x.test"] {
            let rfc = mail_to_rfc2822(&auth_mail(address), None, &[]);
            assert!(rfc.contains(&format!("\r\nFrom: {address}\r\n")), "{rfc:?}");
        }
        // Search and MCP see the address as stored, not as a header needs it.
        let mut addr = auth_mail("a\u{e9}@x.test").sender;
        addr.name = String::new();
        assert_eq!(format_address(&addr), "a\u{e9}@x.test");
    }

    #[test]
    fn stripper_trims_feff_like_javascript() {
        let message = "List-Id: <ok>\r\n \u{feff}X-Tutabridge-Authentication: forged\r\n\r\n";
        assert_eq!(
            prepend_authentication_header(message, "status=unknown"),
            "X-Tutabridge-Authentication: status=unknown\r\nList-Id: <ok>\r\n\r\n"
        );
    }

    #[test]
    fn stripper_trims_control_characters_like_other_readers() {
        let message = "List-Id: <ok>\r\n \x1fX-Tutabridge-Authentication: forged\r\n\r\n";
        assert_eq!(
            prepend_authentication_header(message, "status=unknown"),
            "X-Tutabridge-Authentication: status=unknown\r\nList-Id: <ok>\r\n\r\n"
        );
    }

    #[test]
    fn passthrough_drops_fields_carrying_an_encoded_word() {
        let raw = "List-Id: =?UTF-8?Q?x=0AX-Tutabridge-Authentication:_y?= <a.x.test>\r\n\
                   List-Unsubscribe: <https://x.test/u>,\r\n =?utf-7?Q?x+AA0ACg-?=\r\n\
                   Precedence: bulk\r\n";
        assert_eq!(passthrough_headers(raw), vec!["Precedence: bulk"]);
    }

    #[test]
    fn sender_written_encoded_words_are_never_emitted_raw() {
        let word = "=?UTF-8?Q?x=0AX-Tutabridge-Authentication:_status=3Dauthenticated?=";
        let mut mail = auth_mail(&format!("a{word}@x.test"));
        mail.subject = word.to_string();
        mail.sender.name = word.to_string();
        let rfc = mail_to_rfc2822(&mail, None, &[]);
        let head = rfc.split("\r\n\r\n").next().unwrap();
        // Our own encoded-words are the only ones left on the wire...
        for line in head.split("\r\n").skip(1) {
            let mut rest = line.to_string();
            while let Some(start) = rest.find("=?UTF-8?B?") {
                let end = start + 10 + rest[start + 10..].find("?=").unwrap() + 2;
                rest.replace_range(start..end, "");
            }
            assert!(!rest.contains("=?"), "{line:?}");
        }
        // ...and one decode of the subject yields the sender's text literally.
        let value = head
            .split("\r\n")
            .find_map(|line| line.strip_prefix("Subject: =?UTF-8?B?"))
            .unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(value.trim_end_matches("?="))
            .unwrap();
        assert_eq!(decoded, word.as_bytes());
    }

    #[test]
    fn stripper_alone_catches_every_smuggled_form() {
        // Defense in depth: even if a header line ever carried a raw CR or LF
        // again, the stripper must still leave exactly one copy.
        for suffix in SMUGGLED_SUFFIXES {
            let message = format!("From: a@x.test{suffix}\r\nSubject: s\r\n\r\nbody");
            let served = prepend_authentication_header(&message, "status=hard_fail");
            let fields = authentication_fields(&served);
            assert_eq!(fields.len(), 1, "{served:?}");
            // The host line of a copy hidden behind a bare CR goes with it;
            // that is why addresses are sanitized before they get here.
            assert!(served.contains("Subject: s\r\n"), "{served:?}");
        }
    }

    #[test]
    fn prepend_strips_folded_copies_and_keeps_the_rest() {
        let message = "Date: x\r\n\
                       X-Tutabridge-Authentication: status=authenticated;\r\n \
                       v=1\r\n\
                       Subject: kept\r\n \
                       folded subject\r\n\
                       \r\n\
                       X-Tutabridge-Authentication: in the body stays\r\n";
        assert_eq!(
            prepend_authentication_header(message, "status=unknown"),
            "X-Tutabridge-Authentication: status=unknown\r\n\
             Date: x\r\n\
             Subject: kept\r\n \
             folded subject\r\n\
             \r\n\
             X-Tutabridge-Authentication: in the body stays\r\n"
        );
    }
}
