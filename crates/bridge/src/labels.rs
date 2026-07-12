//! Tuta labels ↔ IMAP keywords.
//!
//! Tuta models labels as `MailSet`s with `kind == Label`; IMAP models the same
//! concept as custom per-message flags — "keywords" (RFC 3501). The
//! [`LabelRegistry`] owns the mapping between the two. It is rebuilt by the
//! syncer / event handler whenever the server's label list changes, lives in
//! the `MailStore`, and is only ever *read* by the IMAP layer (store-backed
//! principle: no API calls on the IMAP read path).

use std::collections::{HashMap, HashSet};
use tutasdk::{GeneratedId, IdTupleGenerated};

/// A Tuta label (`MailSet` with `kind == Label`) as the bridge sees it.
#[derive(Clone, Debug)]
pub struct LabelInfo {
    /// `MailSet` element id — the stable key `Mail.sets` references.
    pub id: String,
    /// `MailSet` list id — with `id` it forms the label's `IdTuple`, which
    /// `ApplyLabelService` takes on the write path.
    pub list_id: String,
    /// Display name as entered in the Tuta app, e.g. `Package Tracking`.
    pub name: String,
    /// `#rrggbb` display color (kept for the Apple Mail flag mapping, phase 4).
    pub color: Option<String>,
}

impl LabelInfo {
    /// The label's full `IdTuple`, as `ApplyLabelService` and `Mail.sets`
    /// reference it.
    pub fn id_tuple(&self) -> IdTupleGenerated {
        IdTupleGenerated::new(
            GeneratedId(self.list_id.clone()),
            GeneratedId(self.id.clone()),
        )
    }
}

/// One label with its assigned IMAP keyword atom.
#[derive(Clone, Debug)]
pub struct LabelEntry {
    pub info: LabelInfo,
    pub keyword: String,
}

/// Bidirectional label ↔ keyword map. Lookups go through the registry in both
/// directions; keyword atoms are never "de-sanitized" back into label names.
#[derive(Clone, Debug, Default)]
pub struct LabelRegistry {
    entries: Vec<LabelEntry>,
    /// Label `MailSet` element id → index into `entries`.
    by_label_id: HashMap<String, usize>,
    /// Lowercased keyword atom → index into `entries`.
    by_keyword: HashMap<String, usize>,
}

impl LabelRegistry {
    pub fn new(mut labels: Vec<LabelInfo>) -> Self {
        // Sort by element id — Tuta's generated ids are time-ordered, so this
        // is creation order. That makes collision suffixes deterministic
        // across restarts: the oldest label keeps the bare atom, later
        // clashes get `_2`, `_3`, … regardless of enumeration order.
        labels.sort_by(|a, b| a.id.cmp(&b.id));

        let mut entries: Vec<LabelEntry> = Vec::with_capacity(labels.len());
        let mut by_label_id = HashMap::with_capacity(labels.len());
        let mut by_keyword = HashMap::with_capacity(labels.len());
        let mut used: HashSet<String> = HashSet::new();
        for info in labels {
            let base = sanitize_keyword(&info.name);
            let mut keyword = base.clone();
            let mut n = 1u32;
            // Clients compare flags case-insensitively (RFC 3501 semantics;
            // Thunderbird lowercases keywords), so two labels whose atoms
            // differ only in case would be indistinguishable — treat that as
            // a collision too.
            while !used.insert(keyword.to_ascii_lowercase()) {
                n += 1;
                keyword = format!("{base}_{n}");
            }
            by_label_id.insert(info.id.clone(), entries.len());
            by_keyword.insert(keyword.to_ascii_lowercase(), entries.len());
            entries.push(LabelEntry { info, keyword });
        }
        Self {
            entries,
            by_label_id,
            by_keyword,
        }
    }

    /// Keyword atoms in registry order, for the FLAGS advertisement.
    pub fn keywords(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|e| e.keyword.as_str())
    }

    /// Keyword for a label's `MailSet` element id. `None` when the id is not
    /// a known label — `Mail.sets` also carries the mail's folder, which is
    /// exactly the entry this lookup is meant to skip.
    pub fn keyword_for_label(&self, label_element_id: &str) -> Option<&str> {
        self.by_label_id
            .get(label_element_id)
            .map(|&i| self.entries[i].keyword.as_str())
    }

    /// Label for a keyword atom a client sent in STORE. Case-insensitive:
    /// flags compare case-insensitively per RFC 3501, and Thunderbird
    /// lowercases every keyword it stores.
    pub fn label_for_keyword(&self, keyword: &str) -> Option<&LabelInfo> {
        self.by_keyword
            .get(&keyword.to_ascii_lowercase())
            .map(|&i| &self.entries[i].info)
    }

    pub fn entries(&self) -> &[LabelEntry] {
        &self.entries
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Color for bridge-created labels. Empty means "no explicit color": the
/// Tuta apps render it with their theme default — the exact value the app
/// itself submits when the user creates a label without touching the color
/// picker.
pub const DEFAULT_LABEL_COLOR: &str = "";

/// Turn a label display name into an IMAP keyword atom.
///
/// Flag keywords are atoms (RFC 3501): ASCII, no spaces, parentheses,
/// brackets, quotes, `%`, `*`, `\`, or control characters. The mapping is
/// deterministic — same name, same atom — and lossy on purpose: common Latin
/// diacritics fold to ASCII, every other run of unrepresentable characters
/// collapses into a single `_`. The registry disambiguates collisions, so
/// lossiness here is cosmetic, not semantic. `$` is kept: it is a valid atom
/// character and the conventional keyword prefix — Thunderbird's built-in
/// tags are `$label1`…`$label5`, and those must round-trip unchanged.
pub fn sanitize_keyword(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    // A pending separator: set while skipping a run of unrepresentable
    // characters, flushed as one `_` only if more atom characters follow —
    // that way atoms never start or end with the filler.
    let mut gap = false;
    for c in name.chars() {
        let folded = if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '$') {
            None
        } else {
            match fold_diacritic(c) {
                Some(f) => Some(f),
                None => {
                    gap = !out.is_empty();
                    continue;
                }
            }
        };
        if gap {
            out.push('_');
            gap = false;
        }
        match folded {
            Some(f) => out.push_str(f),
            None => out.push(c),
        }
    }
    if out.is_empty() {
        // Nothing representable at all (e.g. an emoji-only name). The
        // registry's collision suffixes keep multiple such labels distinct.
        "Label".to_string()
    } else {
        out
    }
}

/// ASCII fold for the Latin diacritics a European mailbox is likely to carry
/// (Polish, German, and the common Western European set — `ä`/`ö`/`ü`/`ß`
/// use the German transliteration convention). Hand-rolled on purpose: a full
/// Unicode normalization crate is not worth a dependency for a cosmetic
/// mapping, and anything unlisted just becomes a `_` in the caller.
fn fold_diacritic(c: char) -> Option<&'static str> {
    Some(match c {
        'ą' | 'á' | 'à' | 'â' | 'ã' | 'å' => "a",
        'Ą' | 'Á' | 'À' | 'Â' | 'Ã' | 'Å' => "A",
        'ä' | 'æ' => "ae",
        'Ä' | 'Æ' => "Ae",
        'ć' | 'ç' | 'č' => "c",
        'Ć' | 'Ç' | 'Č' => "C",
        'ę' | 'é' | 'è' | 'ê' | 'ë' | 'ě' => "e",
        'Ę' | 'É' | 'È' | 'Ê' | 'Ë' | 'Ě' => "E",
        'í' | 'ì' | 'î' | 'ï' => "i",
        'Í' | 'Ì' | 'Î' | 'Ï' => "I",
        'ł' => "l",
        'Ł' => "L",
        'ń' | 'ñ' | 'ň' => "n",
        'Ń' | 'Ñ' | 'Ň' => "N",
        'ó' | 'ò' | 'ô' | 'õ' | 'ø' => "o",
        'Ó' | 'Ò' | 'Ô' | 'Õ' | 'Ø' => "O",
        'ö' | 'œ' => "oe",
        'Ö' | 'Œ' => "Oe",
        'ś' | 'š' => "s",
        'Ś' | 'Š' => "S",
        'ß' => "ss",
        'ú' | 'ù' | 'û' => "u",
        'Ú' | 'Ù' | 'Û' => "U",
        'ü' => "ue",
        'Ü' => "Ue",
        'ý' | 'ÿ' => "y",
        'Ý' => "Y",
        'ź' | 'ż' | 'ž' => "z",
        'Ź' | 'Ż' | 'Ž' => "Z",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn label(id: &str, name: &str) -> LabelInfo {
        LabelInfo {
            id: id.to_string(),
            list_id: "labels".to_string(),
            name: name.to_string(),
            color: None,
        }
    }

    #[test]
    fn sanitize_replaces_spaces_and_specials() {
        assert_eq!(sanitize_keyword("Package Tracking"), "Package_Tracking");
        assert_eq!(sanitize_keyword("a/b\\c\"d(e)f*g%h]i"), "a_b_c_d_e_f_g_h_i");
        // Allowed punctuation passes through.
        assert_eq!(sanitize_keyword("to-do.v2_x"), "to-do.v2_x");
    }

    #[test]
    fn sanitize_folds_diacritics() {
        assert_eq!(sanitize_keyword("Ważne"), "Wazne");
        assert_eq!(sanitize_keyword("Śmieci łączone"), "Smieci_laczone");
        assert_eq!(sanitize_keyword("Größe"), "Groesse");
        assert_eq!(sanitize_keyword("Übersicht"), "Uebersicht");
    }

    #[test]
    fn sanitize_collapses_runs_and_trims_edges() {
        assert_eq!(sanitize_keyword("  Hello   World!!!"), "Hello_World");
        assert_eq!(sanitize_keyword("(((x)))"), "x");
    }

    #[test]
    fn sanitize_unrepresentable_falls_back() {
        assert_eq!(sanitize_keyword("📦"), "Label");
        assert_eq!(sanitize_keyword(""), "Label");
    }

    #[test]
    fn sanitize_keeps_thunderbird_stock_tag_keywords() {
        // TB's built-in tags STORE `$label1`…`$label5`; a lossy mapping here
        // would break create-on-new-keyword for them.
        assert_eq!(sanitize_keyword("$label1"), "$label1");
        assert_eq!(sanitize_keyword("$Forwarded"), "$Forwarded");
    }

    #[test]
    fn registry_maps_ids_and_skips_unknown() {
        let reg = LabelRegistry::new(vec![label("l1", "Ephemeral"), label("l2", "Ważne")]);
        assert_eq!(reg.keyword_for_label("l1"), Some("Ephemeral"));
        assert_eq!(reg.keyword_for_label("l2"), Some("Wazne"));
        // A folder id from Mail.sets is simply not a label.
        assert_eq!(reg.keyword_for_label("inbox"), None);
        assert_eq!(
            reg.keywords().collect::<Vec<_>>(),
            vec!["Ephemeral", "Wazne"]
        );
    }

    #[test]
    fn registry_suffixes_collisions_case_insensitively() {
        // "Zażalenia" and "Żażalenia" both sanitize to the same atom modulo
        // case; "zazalenia" collides case-insensitively.
        let reg = LabelRegistry::new(vec![
            label("a1", "Zażalenia"),
            label("a2", "zażalenia"),
            label("a3", "Zazalenia"),
        ]);
        assert_eq!(reg.keyword_for_label("a1"), Some("Zazalenia"));
        assert_eq!(reg.keyword_for_label("a2"), Some("zazalenia_2"));
        assert_eq!(reg.keyword_for_label("a3"), Some("Zazalenia_3"));
    }

    #[test]
    fn keyword_lookup_is_case_insensitive() {
        let reg = LabelRegistry::new(vec![label("l1", "Package Tracking")]);
        // Thunderbird lowercases keywords; the exact advertised form and any
        // other casing must resolve to the same label.
        for kw in ["Package_Tracking", "package_tracking", "PACKAGE_TRACKING"] {
            let info = reg.label_for_keyword(kw).expect(kw);
            assert_eq!(info.id, "l1");
        }
        assert!(reg.label_for_keyword("unknown").is_none());
        // The IdTuple is what ApplyLabelService consumes.
        let tuple = reg
            .label_for_keyword("package_tracking")
            .unwrap()
            .id_tuple();
        assert_eq!(tuple.list_id.to_string(), "labels");
        assert_eq!(tuple.element_id.to_string(), "l1");
    }

    #[test]
    fn registry_order_is_deterministic_regardless_of_input_order() {
        let forward = LabelRegistry::new(vec![label("a1", "Same"), label("a2", "Same")]);
        let reversed = LabelRegistry::new(vec![label("a2", "Same"), label("a1", "Same")]);
        // The older label (smaller time-ordered id) keeps the bare atom in
        // both cases.
        assert_eq!(forward.keyword_for_label("a1"), Some("Same"));
        assert_eq!(reversed.keyword_for_label("a1"), Some("Same"));
        assert_eq!(forward.keyword_for_label("a2"), Some("Same_2"));
        assert_eq!(reversed.keyword_for_label("a2"), Some("Same_2"));
    }
}
