//! IMAP `SEARCH` parsing + matching (RFC 3501 §6.4.4).
//!
//! This module is deliberately self-contained and free of any `Mail`/session
//! types so it can be unit-tested in isolation: the session layer extracts the
//! handful of comparable fields into a [`MsgView`] and asks [`matches`] whether
//! a given message satisfies a parsed [`SearchKey`].
//!
//! Coverage is metadata-first: subject / from / to / cc, flags, dates, sizes,
//! sequence + UID sets, and boolean composition (`AND` / `OR` / `NOT`). `BODY`
//! and `TEXT` are resolved against the on-disk full-text index: the session
//! queries it once per distinct term ([`collect_body_terms`]) and hands the
//! per-term hit sets to [`matches`] via a [`SearchContext`]. A body term only
//! matches messages whose body has actually been downloaded and indexed.
//!
//! Robustness rule: an unrecognised criterion degrades to a non-restrictive
//! match (it never *hides* messages). Over-inclusion is the safe failure for
//! search; silently dropping a matching mail is not.

use std::collections::{HashMap, HashSet};

/// One element of an IMAP sequence/UID set, e.g. `1`, `3:9`, or `5:*`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SeqRange {
    start: u32,
    /// `None` represents `*` (the largest value present). Since any concrete
    /// value is `<=` the max, an open-ended range is just `value >= start`.
    end: Option<u32>,
}

/// A parsed sequence or UID set (comma-separated [`SeqRange`]s).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SeqSet {
    ranges: Vec<SeqRange>,
}

impl SeqSet {
    fn contains(&self, value: u32) -> bool {
        self.ranges.iter().any(|r| match r.end {
            None => value >= r.start,
            Some(end) => {
                let (lo, hi) = if r.start <= end {
                    (r.start, end)
                } else {
                    (end, r.start)
                };
                value >= lo && value <= hi
            }
        })
    }
}

/// A parsed `SEARCH` query. `And` with an empty vec means "match everything"
/// (the bare `SEARCH ALL` case), which keeps composition simple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchKey {
    All,
    And(Vec<SearchKey>),
    Or(Box<SearchKey>, Box<SearchKey>),
    Not(Box<SearchKey>),

    // Flag predicates. We only ever expose `\Seen` and `\Deleted` over FETCH,
    // so the others resolve to a fixed answer to stay consistent with what a
    // client sees in FLAGS (e.g. nothing is ever `\Answered`).
    Seen,
    Unseen,
    Answered,
    Unanswered,
    Flagged,
    Unflagged,
    Draft,
    Undraft,
    Deleted,
    Undeleted,
    Recent,
    New,
    Old,
    /// A keyword (Thunderbird tag, i.e. a Tuta label) the mail carries.
    Keyword(String),
    Unkeyword(String),

    // Header / string predicates (case-insensitive substring).
    Subject(String),
    From(String),
    To(String),
    Cc(String),
    Bcc(String),
    Body(String),
    Text(String),
    Header(String, String),

    // Date predicates, stored as a day number (days since the Unix epoch).
    // `Before`/`On`/`Since` test the internal (received) date.
    Before(i64),
    On(i64),
    Since(i64),
    SentBefore(i64),
    SentOn(i64),
    SentSince(i64),

    // Size predicates (against RFC822.SIZE).
    Larger(u64),
    Smaller(u64),

    Uid(SeqSet),
    Sequence(SeqSet),

    /// A criterion the client got wrong; the whole SEARCH answers BAD rather
    /// than an empty success that would read as "no such mail".
    Invalid(String),
}

/// The slice of a message the matcher needs. Derived fields (From / To / Cc /
/// Bcc / headers) are owned because the session builds them per search; the
/// cheap fields (subject, body) borrow directly from the cached message.
pub struct MsgView<'a> {
    pub seq: u32,
    pub uid: u32,
    /// Tuta element id — the key used to look up full-text body hits.
    pub element_id: &'a str,
    pub subject: &'a str,
    /// Formatted `From` (name + address), for `FROM` substring matching.
    pub from: String,
    pub to: String,
    pub cc: String,
    pub bcc: String,
    /// Raw header block (everything before the blank line), for `HEADER`/`TEXT`.
    pub headers: String,
    /// Received date in epoch millis (also our INTERNALDATE).
    pub date_ms: u64,
    /// Sent date in epoch millis; falls back to `date_ms` when unknown.
    pub sent_ms: u64,
    pub unread: bool,
    pub deleted: bool,
    pub size: u64,
    /// The keywords FETCH FLAGS reports for this mail.
    pub keywords: Vec<&'a str>,
}

/// Pre-resolved full-text results for one SEARCH: maps each `BODY`/`TEXT` term
/// to the set of element ids whose indexed body matched it. Built by the
/// session from the on-disk index before evaluating the query.
#[derive(Default)]
pub struct SearchContext {
    pub body_hits: HashMap<String, HashSet<String>>,
}

impl SearchContext {
    pub fn empty() -> Self {
        Self::default()
    }

    fn body_matches(&self, term: &str, element_id: &str) -> bool {
        self.body_hits
            .get(term)
            .is_some_and(|ids| ids.contains(element_id))
    }
}

/// Collect the distinct `BODY`/`TEXT` term arguments in a parsed query, so the
/// session can resolve each against the full-text index exactly once.
pub fn collect_body_terms(key: &SearchKey) -> Vec<String> {
    let mut terms = Vec::new();
    collect_body_terms_into(key, &mut terms);
    terms.sort();
    terms.dedup();
    terms
}

fn collect_body_terms_into(key: &SearchKey, out: &mut Vec<String>) {
    match key {
        SearchKey::And(keys) => keys.iter().for_each(|k| collect_body_terms_into(k, out)),
        SearchKey::Or(a, b) => {
            collect_body_terms_into(a, out);
            collect_body_terms_into(b, out);
        }
        SearchKey::Not(k) => collect_body_terms_into(k, out),
        SearchKey::Body(s) | SearchKey::Text(s) => out.push(s.clone()),
        _ => {}
    }
}

fn contains_ci(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

/// Does any header line whose field name equals `name` contain `value`?
/// With an empty `value`, matches when the header is merely present.
fn header_contains(headers: &str, name: &str, value: &str) -> bool {
    let name_lc = name.to_lowercase();
    for line in headers.split("\r\n") {
        if let Some((field, val)) = line.split_once(':') {
            if field.trim().to_lowercase() == name_lc {
                if value.is_empty() || contains_ci(val, value) {
                    return true;
                }
            }
        }
    }
    false
}

fn day_number(ms: u64) -> i64 {
    (ms / 86_400_000) as i64
}

/// Evaluate a parsed query against one message, consulting `ctx` for the
/// full-text results of any `BODY`/`TEXT` terms.
pub fn matches(key: &SearchKey, m: &MsgView, ctx: &SearchContext) -> bool {
    match key {
        SearchKey::All => true,
        SearchKey::And(keys) => keys.iter().all(|k| matches(k, m, ctx)),
        SearchKey::Or(a, b) => matches(a, m, ctx) || matches(b, m, ctx),
        SearchKey::Not(k) => !matches(k, m, ctx),

        SearchKey::Seen => !m.unread,
        SearchKey::Unseen => m.unread,
        SearchKey::Answered => false,
        SearchKey::Unanswered => true,
        SearchKey::Flagged => false,
        SearchKey::Unflagged => true,
        SearchKey::Draft => false,
        SearchKey::Undraft => true,
        SearchKey::Deleted => m.deleted,
        SearchKey::Undeleted => !m.deleted,
        SearchKey::Recent => false,
        SearchKey::New => false, // RECENT && UNSEEN — we never flag \Recent
        SearchKey::Old => true,
        // Flags compare case-insensitively (RFC 3501), and Thunderbird
        // lowercases the keywords it sends.
        SearchKey::Keyword(k) => m.keywords.iter().any(|kw| kw.eq_ignore_ascii_case(k)),
        SearchKey::Unkeyword(k) => !m.keywords.iter().any(|kw| kw.eq_ignore_ascii_case(k)),

        SearchKey::Subject(s) => contains_ci(m.subject, s),
        SearchKey::From(s) => contains_ci(&m.from, s),
        SearchKey::To(s) => contains_ci(&m.to, s),
        SearchKey::Cc(s) => contains_ci(&m.cc, s),
        SearchKey::Bcc(s) => contains_ci(&m.bcc, s),
        SearchKey::Body(s) => ctx.body_matches(s, m.element_id),
        SearchKey::Text(s) => contains_ci(&m.headers, s) || ctx.body_matches(s, m.element_id),
        SearchKey::Header(name, val) => header_contains(&m.headers, name, val),

        SearchKey::Before(d) => day_number(m.date_ms) < *d,
        SearchKey::On(d) => day_number(m.date_ms) == *d,
        SearchKey::Since(d) => day_number(m.date_ms) >= *d,
        SearchKey::SentBefore(d) => day_number(m.sent_ms) < *d,
        SearchKey::SentOn(d) => day_number(m.sent_ms) == *d,
        SearchKey::SentSince(d) => day_number(m.sent_ms) >= *d,

        SearchKey::Larger(n) => m.size > *n,
        SearchKey::Smaller(n) => m.size < *n,

        SearchKey::Uid(set) => set.contains(m.uid),
        SearchKey::Invalid(_) => false,
        SearchKey::Sequence(set) => set.contains(m.seq),
    }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    LParen,
    RParen,
    /// A bare atom (a keyword or an unquoted argument like a date or seq-set).
    Atom(String),
    /// A double-quoted string argument (may hold spaces / UTF-8).
    Quoted(String),
}

fn tokenize(input: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();
    while let Some(&c) = chars.peek() {
        match c {
            ' ' | '\t' | '\r' | '\n' => {
                chars.next();
            }
            '(' => {
                chars.next();
                tokens.push(Token::LParen);
            }
            ')' => {
                chars.next();
                tokens.push(Token::RParen);
            }
            '"' => {
                chars.next(); // opening quote
                let mut s = String::new();
                while let Some(ch) = chars.next() {
                    match ch {
                        '\\' => {
                            if let Some(escaped) = chars.next() {
                                s.push(escaped);
                            }
                        }
                        '"' => break,
                        _ => s.push(ch),
                    }
                }
                tokens.push(Token::Quoted(s));
            }
            _ => {
                let mut s = String::new();
                while let Some(&ch) = chars.peek() {
                    if ch == ' ' || ch == '\t' || ch == '(' || ch == ')' || ch == '"' {
                        break;
                    }
                    s.push(ch);
                    chars.next();
                }
                tokens.push(Token::Atom(s));
            }
        }
    }
    tokens
}

/// Parse a full SEARCH argument string into a single composite key.
///
/// Anything malformed becomes [`SearchKey::Invalid`] (the session answers
/// BAD) rather than a fallback: a fallback is a silent wrong answer, and
/// under `NOT` an empty success.
pub fn parse(args: &str) -> SearchKey {
    let tokens = tokenize(args);
    let mut i = 0;
    let keys = parse_key_list(&tokens, &mut i, false);
    if keys.is_empty() {
        return SearchKey::Invalid("SEARCH needs at least one criterion".to_owned());
    }
    fold_and(keys)
}

/// Client text quoted for a response line: response text is 7-bit and one
/// line, so anything else is escaped.
fn echo(s: &str) -> String {
    format!("\"{}\"", s.escape_default())
}

fn fold_and(mut keys: Vec<SearchKey>) -> SearchKey {
    match keys.len() {
        0 => SearchKey::All,
        1 => keys.pop().unwrap(),
        _ => SearchKey::And(keys),
    }
}

/// Parse a run of keys until end-of-input or (when `in_group`) the matching
/// `)`. Consumes the closing paren.
fn parse_key_list(tokens: &[Token], i: &mut usize, in_group: bool) -> Vec<SearchKey> {
    let mut keys = Vec::new();
    while *i < tokens.len() {
        if tokens[*i] == Token::RParen {
            *i += 1; // consume ')'
            if in_group {
                return keys;
            }
            keys.push(SearchKey::Invalid("unbalanced \")\"".to_owned()));
            continue;
        }
        match parse_key(tokens, i) {
            Some(k) => keys.push(k),
            None => break,
        }
    }
    if in_group {
        keys.push(SearchKey::Invalid("unbalanced \"(\"".to_owned()));
    }
    keys
}

/// Read the next token as a string argument (atom or quoted), advancing.
/// `KEYWORD`/`UNKEYWORD` take a flag keyword, which is an atom (RFC 3501):
/// a missing one, or one with atom-specials (`\Seen` is a system flag, not a
/// keyword), is a client error.
fn keyword_key(
    tokens: &[Token],
    i: &mut usize,
    name: &str,
    ctor: fn(String) -> SearchKey,
) -> SearchKey {
    match next_arg(tokens, i) {
        Some(keyword) if is_flag_keyword(&keyword) => ctor(keyword),
        Some(other) => SearchKey::Invalid(format!("{name} {} is not a keyword atom", echo(&other))),
        None => SearchKey::Invalid(format!("{name} needs a keyword")),
    }
}

fn is_flag_keyword(s: &str) -> bool {
    !s.is_empty()
        && s.chars().all(|c| {
            c.is_ascii_graphic() && !matches!(c, '(' | ')' | '{' | '%' | '*' | '"' | '\\' | ']')
        })
}

impl SearchKey {
    /// Why the query is malformed, if any criterion in it is.
    pub fn invalid_reason(&self) -> Option<&str> {
        match self {
            SearchKey::Invalid(reason) => Some(reason),
            SearchKey::And(keys) => keys.iter().find_map(SearchKey::invalid_reason),
            SearchKey::Or(a, b) => a.invalid_reason().or_else(|| b.invalid_reason()),
            SearchKey::Not(k) => k.invalid_reason(),
            _ => None,
        }
    }
}

fn next_arg(tokens: &[Token], i: &mut usize) -> Option<String> {
    match tokens.get(*i) {
        Some(Token::Atom(s)) | Some(Token::Quoted(s)) => {
            let s = s.clone();
            *i += 1;
            Some(s)
        }
        _ => None,
    }
}

fn parse_key(tokens: &[Token], i: &mut usize) -> Option<SearchKey> {
    let token = tokens.get(*i)?.clone();
    *i += 1;

    match token {
        Token::LParen => {
            let keys = parse_key_list(tokens, i, true);
            Some(if keys.is_empty() {
                SearchKey::Invalid("empty \"()\"".to_owned())
            } else {
                fold_and(keys)
            })
        }
        Token::RParen => None,
        Token::Quoted(text) => Some(SearchKey::Invalid(format!(
            "{} is not a search key",
            echo(&text)
        ))),
        Token::Atom(atom) => Some(parse_atom_key(&atom, tokens, i)),
    }
}

fn parse_atom_key(atom: &str, tokens: &[Token], i: &mut usize) -> SearchKey {
    let key = atom.to_uppercase();
    match key.as_str() {
        "ALL" => SearchKey::All,
        "ANSWERED" => SearchKey::Answered,
        "UNANSWERED" => SearchKey::Unanswered,
        "SEEN" => SearchKey::Seen,
        "UNSEEN" => SearchKey::Unseen,
        "FLAGGED" => SearchKey::Flagged,
        "UNFLAGGED" => SearchKey::Unflagged,
        "DELETED" => SearchKey::Deleted,
        "UNDELETED" => SearchKey::Undeleted,
        "DRAFT" => SearchKey::Draft,
        "UNDRAFT" => SearchKey::Undraft,
        "RECENT" => SearchKey::Recent,
        "NEW" => SearchKey::New,
        "OLD" => SearchKey::Old,

        "OR" => {
            let missing = || SearchKey::Invalid("OR needs two criteria".to_owned());
            let a = parse_key(tokens, i).unwrap_or_else(missing);
            let b = parse_key(tokens, i).unwrap_or_else(missing);
            SearchKey::Or(Box::new(a), Box::new(b))
        }
        "NOT" => {
            let a = parse_key(tokens, i)
                .unwrap_or_else(|| SearchKey::Invalid("NOT needs a criterion".to_owned()));
            SearchKey::Not(Box::new(a))
        }

        // `CHARSET <name>` is a prefix, not a criterion — skip the name and
        // parse the key that follows.
        "CHARSET" => match next_arg(tokens, i) {
            Some(_) => parse_key(tokens, i).unwrap_or_else(|| {
                SearchKey::Invalid("CHARSET needs a criterion after it".to_owned())
            }),
            None => SearchKey::Invalid("CHARSET needs a name".to_owned()),
        },

        "SUBJECT" => str_key(tokens, i, "SUBJECT", SearchKey::Subject),
        "FROM" => str_key(tokens, i, "FROM", SearchKey::From),
        "TO" => str_key(tokens, i, "TO", SearchKey::To),
        "CC" => str_key(tokens, i, "CC", SearchKey::Cc),
        "BCC" => str_key(tokens, i, "BCC", SearchKey::Bcc),
        "BODY" => str_key(tokens, i, "BODY", SearchKey::Body),
        "TEXT" => str_key(tokens, i, "TEXT", SearchKey::Text),
        "KEYWORD" => keyword_key(tokens, i, "KEYWORD", SearchKey::Keyword),
        "UNKEYWORD" => keyword_key(tokens, i, "UNKEYWORD", SearchKey::Unkeyword),
        "HEADER" => match (next_arg(tokens, i), next_arg(tokens, i)) {
            (Some(name), Some(value)) => SearchKey::Header(name, value),
            _ => SearchKey::Invalid("HEADER needs a field name and a string".to_owned()),
        },

        "BEFORE" => date_key(tokens, i, "BEFORE", SearchKey::Before),
        "ON" => date_key(tokens, i, "ON", SearchKey::On),
        "SINCE" => date_key(tokens, i, "SINCE", SearchKey::Since),
        "SENTBEFORE" => date_key(tokens, i, "SENTBEFORE", SearchKey::SentBefore),
        "SENTON" => date_key(tokens, i, "SENTON", SearchKey::SentOn),
        "SENTSINCE" => date_key(tokens, i, "SENTSINCE", SearchKey::SentSince),

        "LARGER" => size_key(tokens, i, "LARGER", SearchKey::Larger),
        "SMALLER" => size_key(tokens, i, "SMALLER", SearchKey::Smaller),

        "UID" => match next_arg(tokens, i) {
            Some(set) if is_seqset(&set) => SearchKey::Uid(parse_seqset(&set)),
            Some(other) => SearchKey::Invalid(format!("UID {} is not a set", echo(&other))),
            None => SearchKey::Invalid("UID needs a set".to_owned()),
        },

        // Not a recognised keyword: a bare sequence set is a criterion of its
        // own; anything else is a key we do not know.
        _ => {
            if is_seqset(atom) {
                SearchKey::Sequence(parse_seqset(atom))
            } else {
                SearchKey::Invalid(format!("unknown search key {}", echo(atom)))
            }
        }
    }
}

fn str_key(
    tokens: &[Token],
    i: &mut usize,
    name: &str,
    ctor: fn(String) -> SearchKey,
) -> SearchKey {
    match next_arg(tokens, i) {
        Some(text) => ctor(text),
        None => SearchKey::Invalid(format!("{name} needs a string")),
    }
}

fn date_key(tokens: &[Token], i: &mut usize, name: &str, ctor: fn(i64) -> SearchKey) -> SearchKey {
    match next_arg(tokens, i) {
        Some(text) => match parse_imap_date(&text) {
            Some(day) => ctor(day),
            None => SearchKey::Invalid(format!(
                "{name} {} is not a date like 1-Feb-2024",
                echo(&text)
            )),
        },
        None => SearchKey::Invalid(format!("{name} needs a date")),
    }
}

fn size_key(tokens: &[Token], i: &mut usize, name: &str, ctor: fn(u64) -> SearchKey) -> SearchKey {
    match next_arg(tokens, i) {
        Some(text) => match text.parse::<u64>() {
            Ok(n) => ctor(n),
            Err(_) => SearchKey::Invalid(format!("{name} {} is not a size", echo(&text))),
        },
        None => SearchKey::Invalid(format!("{name} needs a size")),
    }
}

fn is_seqset(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_digit() || c == ':' || c == ',' || c == '*')
}

fn parse_seqset(s: &str) -> SeqSet {
    let mut ranges = Vec::new();
    for part in s.split(',') {
        if part.is_empty() {
            continue;
        }
        if let Some((a, b)) = part.split_once(':') {
            let start = if a == "*" { 0 } else { a.parse().unwrap_or(0) };
            let end = if b == "*" { None } else { b.parse().ok() };
            ranges.push(SeqRange { start, end });
        } else if part == "*" {
            ranges.push(SeqRange {
                start: 0,
                end: None,
            });
        } else if let Ok(n) = part.parse::<u32>() {
            ranges.push(SeqRange {
                start: n,
                end: Some(n),
            });
        }
    }
    SeqSet { ranges }
}

/// Parse an IMAP date (`dd-Mon-yyyy`, e.g. `1-Feb-2020`) into a day number.
fn parse_imap_date(s: &str) -> Option<i64> {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 3 {
        return None;
    }
    let day: i64 = parts[0].parse().ok()?;
    let month = match parts[1].to_lowercase().as_str() {
        "jan" => 1,
        "feb" => 2,
        "mar" => 3,
        "apr" => 4,
        "may" => 5,
        "jun" => 6,
        "jul" => 7,
        "aug" => 8,
        "sep" => 9,
        "oct" => 10,
        "nov" => 11,
        "dec" => 12,
        _ => return None,
    };
    let year: i64 = parts[2].parse().ok()?;
    Some(days_from_civil(year, month, day))
}

/// Days since 1970-01-01 (Howard Hinnant's `days_from_civil`).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

#[cfg(test)]
mod tests {
    use super::*;

    fn day(y: i64, m: i64, d: i64) -> i64 {
        days_from_civil(y, m, d)
    }

    fn view() -> MsgView<'static> {
        MsgView {
            seq: 1,
            uid: 10,
            element_id: "mail1",
            subject: "Hello World",
            from: "Alice <alice@example.com>".into(),
            to: "Bob <bob@example.com>".into(),
            cc: String::new(),
            bcc: String::new(),
            headers:
                "From: Alice <alice@example.com>\r\nSubject: Hello World\r\nMessage-ID: <abc@x>"
                    .into(),
            date_ms: (day(2022, 9, 22) as u64) * 86_400_000 + 3_600_000,
            sent_ms: (day(2022, 9, 22) as u64) * 86_400_000 + 3_600_000,
            unread: true,
            deleted: false,
            size: 5000,
            keywords: vec!["Work", "$label1"],
        }
    }

    #[test]
    fn malformed_keyword_criteria_are_invalid_not_empty() {
        for query in [
            "KEYWORD",
            "KEYWORD \\Seen",
            "KEYWORD (SEEN)",
            "(KEYWORD) SEEN",
            "NOT UNKEYWORD",
            "OR SEEN KEYWORD a*b",
        ] {
            assert!(parse(query).invalid_reason().is_some(), "{query}");
        }
        for query in ["KEYWORD work", "KEYWORD $label1", "UNKEYWORD \"work\""] {
            assert!(parse(query).invalid_reason().is_none(), "{query}");
        }
    }

    #[test]
    fn keyword_matches_case_insensitively() {
        let m = view();
        let ctx = SearchContext::default();
        assert!(matches(&parse("KEYWORD work"), &m, &ctx));
        assert!(matches(&parse("KEYWORD $Label1"), &m, &ctx));
        assert!(!matches(&parse("KEYWORD Home"), &m, &ctx));
        assert!(!matches(&parse("UNKEYWORD WORK"), &m, &ctx));
        assert!(matches(&parse("UNKEYWORD Home"), &m, &ctx));
        // The atom is consumed: the next key still applies.
        assert!(!matches(&parse("KEYWORD work SEEN"), &m, &ctx));
    }

    /// A context where the given terms all hit our test message ("mail1").
    fn ctx_hitting(terms: &[&str]) -> SearchContext {
        let mut body_hits = HashMap::new();
        for t in terms {
            body_hits.insert((*t).to_string(), HashSet::from(["mail1".to_string()]));
        }
        SearchContext { body_hits }
    }

    fn no_ctx() -> SearchContext {
        SearchContext::empty()
    }

    // --- tokenizer ---

    #[test]
    fn tokenize_quoted_and_atoms() {
        let t = tokenize(r#"SUBJECT "hello world" UNSEEN"#);
        assert_eq!(
            t,
            vec![
                Token::Atom("SUBJECT".into()),
                Token::Quoted("hello world".into()),
                Token::Atom("UNSEEN".into()),
            ]
        );
    }

    #[test]
    fn tokenize_parens() {
        let t = tokenize("(OR A B)");
        assert_eq!(t[0], Token::LParen);
        assert_eq!(t[4], Token::RParen);
    }

    // --- parser ---

    #[test]
    fn parse_requires_a_criterion() {
        // RFC 3501: SEARCH takes at least one key.
        assert!(parse("").invalid_reason().is_some());
        assert_eq!(parse("ALL"), SearchKey::All);
    }

    #[test]
    fn parse_implicit_and() {
        let k = parse(r#"UNSEEN SUBJECT "foo""#);
        assert_eq!(
            k,
            SearchKey::And(vec![SearchKey::Unseen, SearchKey::Subject("foo".into())])
        );
    }

    #[test]
    fn parse_or_and_not() {
        let k = parse(r#"OR FROM "a" NOT SEEN"#);
        match k {
            SearchKey::Or(a, b) => {
                assert_eq!(*a, SearchKey::From("a".into()));
                assert_eq!(*b, SearchKey::Not(Box::new(SearchKey::Seen)));
            }
            _ => panic!("expected OR, got {k:?}"),
        }
    }

    #[test]
    fn parse_group() {
        let k = parse(r#"(SUBJECT "x" SUBJECT "y") UNSEEN"#);
        assert_eq!(
            k,
            SearchKey::And(vec![
                SearchKey::And(vec![
                    SearchKey::Subject("x".into()),
                    SearchKey::Subject("y".into()),
                ]),
                SearchKey::Unseen,
            ])
        );
    }

    #[test]
    fn parse_charset_prefix_is_skipped() {
        let k = parse(r#"CHARSET UTF-8 BODY "x""#);
        assert_eq!(k, SearchKey::Body("x".into()));
    }

    #[test]
    fn parse_header() {
        let k = parse(r#"HEADER Message-ID "<abc@x>""#);
        assert_eq!(k, SearchKey::Header("Message-ID".into(), "<abc@x>".into()));
    }

    #[test]
    fn parse_date() {
        assert_eq!(parse("SINCE 1-Feb-2020"), SearchKey::Since(day(2020, 2, 1)));
        assert_eq!(
            parse("BEFORE 15-Dec-2021"),
            SearchKey::Before(day(2021, 12, 15))
        );
    }

    #[test]
    fn parse_bad_date_is_invalid() {
        assert!(parse("SINCE not-a-date").invalid_reason().is_some());
    }

    #[test]
    fn parse_seqset_and_uid() {
        assert_eq!(parse("1:5"), SearchKey::Sequence(parse_seqset("1:5")));
        assert_eq!(parse("UID 3:*"), SearchKey::Uid(parse_seqset("3:*")));
    }

    #[test]
    fn parse_unknown_key_is_invalid() {
        // Matching all would be a silent wrong answer, and under NOT an
        // empty success (issue #16).
        assert!(parse("XFOOBAR").invalid_reason().is_some());
    }

    #[test]
    fn every_malformed_criterion_is_invalid_even_under_not() {
        for query in [
            "NOT FOOBAR",
            "NOT BEFORE 99-Foo-2020",
            "NOT SMALLER abc",
            "LARGER",
            "UID abc",
            "UID",
            "HEADER",
            "HEADER Subject",
            "NOT SUBJECT",
            "NOT \"x\"",
            "OR SEEN",
            "NOT",
            "CHARSET",
            "CHARSET UTF-8",
            "(SEEN",
            "SEEN)",
            "()",
            "KEYWORD work FOOBAR",
        ] {
            assert!(parse(query).invalid_reason().is_some(), "{query}");
        }
        for query in [
            "SUBJECT \"\"",
            "HEADER Message-ID \"\"",
            "CHARSET UTF-8 SUBJECT x",
            "OR (SEEN) NOT DELETED",
            "1:5 UID 3:*",
        ] {
            assert!(parse(query).invalid_reason().is_none(), "{query}");
        }
    }

    #[test]
    fn invalid_reasons_are_one_7_bit_line() {
        let reason = parse("KEYWORD \"za\u{17c}\r\nx\"")
            .invalid_reason()
            .unwrap()
            .to_owned();
        assert!(
            reason.is_ascii() && !reason.contains(['\r', '\n']),
            "{reason}"
        );
    }

    // --- seqset ---

    #[test]
    fn seqset_membership() {
        let s = parse_seqset("1,3,5:9");
        assert!(s.contains(1));
        assert!(!s.contains(2));
        assert!(s.contains(3));
        assert!(s.contains(7));
        assert!(!s.contains(10));
    }

    #[test]
    fn seqset_open_ended_star() {
        let s = parse_seqset("100:*");
        assert!(!s.contains(99));
        assert!(s.contains(100));
        assert!(s.contains(999_999));
    }

    // --- matcher ---

    #[test]
    fn match_subject_ci() {
        let c = no_ctx();
        assert!(matches(&SearchKey::Subject("hello".into()), &view(), &c));
        assert!(matches(&SearchKey::Subject("WORLD".into()), &view(), &c));
        assert!(!matches(&SearchKey::Subject("nope".into()), &view(), &c));
    }

    #[test]
    fn match_from_to() {
        let c = no_ctx();
        assert!(matches(&SearchKey::From("alice".into()), &view(), &c));
        assert!(matches(&SearchKey::To("bob@example".into()), &view(), &c));
        assert!(!matches(&SearchKey::Cc("anyone".into()), &view(), &c));
    }

    #[test]
    fn match_flags_consistent_with_fetch() {
        let v = view(); // unread, not deleted
        let c = no_ctx();
        assert!(matches(&SearchKey::Unseen, &v, &c));
        assert!(!matches(&SearchKey::Seen, &v, &c));
        assert!(!matches(&SearchKey::Answered, &v, &c));
        assert!(matches(&SearchKey::Unanswered, &v, &c));
        assert!(!matches(&SearchKey::Flagged, &v, &c));
        assert!(!matches(&SearchKey::Deleted, &v, &c));
        assert!(matches(&SearchKey::Undeleted, &v, &c));
    }

    #[test]
    fn match_dates() {
        let v = view(); // 2022-09-22
        let c = no_ctx();
        assert!(matches(&SearchKey::Since(day(2022, 1, 1)), &v, &c));
        assert!(matches(&SearchKey::Before(day(2023, 1, 1)), &v, &c));
        assert!(matches(&SearchKey::On(day(2022, 9, 22)), &v, &c));
        assert!(!matches(&SearchKey::On(day(2022, 9, 23)), &v, &c));
        assert!(!matches(&SearchKey::Since(day(2023, 1, 1)), &v, &c));
    }

    #[test]
    fn match_size() {
        let v = view(); // size 5000
        let c = no_ctx();
        assert!(matches(&SearchKey::Larger(4000), &v, &c));
        assert!(!matches(&SearchKey::Larger(6000), &v, &c));
        assert!(matches(&SearchKey::Smaller(6000), &v, &c));
    }

    #[test]
    fn match_body_uses_fts_context() {
        let v = view();
        let c = ctx_hitting(&["brown"]);
        assert!(matches(&SearchKey::Body("brown".into()), &v, &c));
        // A term with no FTS hit doesn't match, even though it's a real word.
        assert!(!matches(&SearchKey::Body("missing".into()), &v, &c));
    }

    #[test]
    fn match_text_spans_headers_and_body() {
        let v = view();
        let c = ctx_hitting(&["quick"]);
        // Header hit, no body hit needed.
        assert!(matches(
            &SearchKey::Text("Message-ID".into()),
            &v,
            &no_ctx()
        ));
        // Body hit via the FTS context.
        assert!(matches(&SearchKey::Text("quick".into()), &v, &c));
        // Neither headers nor index: no match.
        assert!(!matches(&SearchKey::Text("quick".into()), &v, &no_ctx()));
    }

    #[test]
    fn match_body_without_index_never_matches() {
        let v = view();
        assert!(!matches(&SearchKey::Body("brown".into()), &v, &no_ctx()));
        // TEXT still matches on headers without any index.
        assert!(matches(&SearchKey::Text("Subject".into()), &v, &no_ctx()));
    }

    #[test]
    fn collect_body_terms_finds_nested_terms() {
        let k = parse(r#"OR BODY "alpha" (TEXT "beta" SUBJECT "x") NOT BODY "alpha""#);
        // Note: top level is `OR <a> <b>` then trailing keys folded into AND.
        let terms = collect_body_terms(&k);
        assert_eq!(terms, vec!["alpha".to_string(), "beta".to_string()]);
    }

    #[test]
    fn match_header() {
        let v = view();
        let c = no_ctx();
        assert!(matches(
            &SearchKey::Header("message-id".into(), "abc".into()),
            &v,
            &c
        ));
        assert!(!matches(
            &SearchKey::Header("message-id".into(), "zzz".into()),
            &v,
            &c
        ));
        // Presence-only (empty value).
        assert!(matches(
            &SearchKey::Header("subject".into(), "".into()),
            &v,
            &c
        ));
        assert!(!matches(
            &SearchKey::Header("x-nope".into(), "".into()),
            &v,
            &c
        ));
    }

    #[test]
    fn match_uid_and_seq() {
        let v = view(); // seq 1, uid 10
        let c = no_ctx();
        assert!(matches(&SearchKey::Uid(parse_seqset("5:15")), &v, &c));
        assert!(!matches(&SearchKey::Uid(parse_seqset("1:5")), &v, &c));
        assert!(matches(&SearchKey::Sequence(parse_seqset("1")), &v, &c));
    }

    #[test]
    fn match_boolean_composition() {
        let v = view();
        let c = no_ctx();
        let k = parse(r#"UNSEEN SUBJECT "hello""#);
        assert!(matches(&k, &v, &c));
        let k = parse(r#"SEEN SUBJECT "hello""#);
        assert!(!matches(&k, &v, &c));
        let k = parse(r#"OR SEEN SUBJECT "hello""#);
        assert!(matches(&k, &v, &c));
        let k = parse("NOT SEEN");
        assert!(matches(&k, &v, &c));
    }
}
