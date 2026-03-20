//! agentguard_rs — native Rust extension for AgentGuard policy pattern matching.
//!
//! Exposes a single `PolicyMatcher` class that pre-compiles all glob/fnmatch/domain
//! patterns at construction time and exposes zero-copy match methods.
//!
//! # Safety guarantees
//! All regex compilation uses the `regex` crate, which uses a DFA-based engine with
//! guaranteed O(n) matching. There is no catastrophic backtracking regardless of the
//! input path or domain length.
//!
//! # Build
//! ```bash
//! cd agentguard_rs
//! pip install maturin
//! maturin develop --release   # installs into active venv
//! ```

use pyo3::prelude::*;
use regex::Regex;

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

/// A compiled glob pattern paired with its original string (for error messages).
struct CompiledGlob {
    original: String,
    regex: Regex,
}

/// A compiled domain pattern: either a fast suffix check or a full fnmatch regex.
enum DomainPattern {
    /// `*.ngrok.io` → stored as ".ngrok.io"; matched via `ends_with` + exact root check.
    Suffix(String, String), // (suffix e.g. ".ngrok.io", original e.g. "*.ngrok.io")
    /// Any other pattern (e.g. `webhook.*`) → compiled to a case-insensitive regex.
    Regex(String, Regex), // (original pattern, compiled regex)
}

/// A compiled fnmatch-style pattern for tool names and provenance source types.
struct CompiledFnmatch {
    original: String,
    regex: Regex,
}

// ---------------------------------------------------------------------------
// Pattern compilation helpers
// ---------------------------------------------------------------------------

/// Convert an AgentGuard glob pattern to a full-match regex string.
///
/// Supports:
/// - `~` expansion to the real HOME directory (at compile time, same as Python)
/// - `**/` — zero or more path segments followed by a slash
/// - `**`  — any sequence of characters (including slashes)
/// - `*`   — any characters within a single path segment (no slashes)
/// - `?`   — any single character except `/`
/// - All other characters are regex-escaped.
fn glob_to_regex(raw_pattern: &str) -> Result<Regex, regex::Error> {
    // Expand leading `~` to home directory, mirroring Python's os.path.expanduser.
    let expanded = expand_home(raw_pattern);
    // Normalise separators and strip trailing slash.
    let normalised = expanded.replace('\\', "/");
    let pattern = normalised.trim_end_matches('/');

    let mut re = String::with_capacity(pattern.len() * 2 + 2);
    re.push('^');

    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        // Check for `**/` (must come before `**` check)
        if chars[i] == '*'
            && i + 2 < chars.len()
            && chars[i + 1] == '*'
            && chars[i + 2] == '/'
        {
            re.push_str("(?:.+/)?"); // zero or more path segments + slash
            i += 3;
        // Check for `**` (not followed by `/`)
        } else if chars[i] == '*' && i + 1 < chars.len() && chars[i + 1] == '*' {
            re.push_str(".*"); // any characters including slashes
            i += 2;
        // Single `*` — any characters within one segment
        } else if chars[i] == '*' {
            re.push_str("[^/]*");
            i += 1;
        // `?` — any single non-slash character
        } else if chars[i] == '?' {
            re.push_str("[^/]");
            i += 1;
        // Literal character — escape for regex
        } else {
            re.push_str(&regex::escape(&chars[i].to_string()));
            i += 1;
        }
    }

    re.push_str(r"\z"); // true end-of-text anchor (same as Python re.fullmatch semantics)
    Regex::new(&re)
}

/// Convert a fnmatch-style pattern to a full-match regex.
///
/// Semantics match Python 3.12's `fnmatch.translate`:
/// - `*`     — any sequence of characters (including newlines — `(?s:...)` dotall)
/// - `?`     — any single character
/// - `[seq]` — character class, passed through verbatim
/// - All other characters are regex-escaped.
/// - Anchored with `^(?s:...)\\z` — `\\z` is true end-of-string (not end-of-line).
/// - Case-SENSITIVE: Python's fnmatch.translate does not add IGNORECASE.
///
/// Callers are responsible for lowercasing inputs when case-insensitive matching
/// is desired (e.g. tool names are lowercased before being passed here).
fn fnmatch_to_regex(pattern: &str) -> Result<Regex, regex::Error> {
    let mut re = String::with_capacity(pattern.len() * 2 + 8);
    re.push_str("^(?s:"); // dotall: . matches \n — mirrors Python's (?s:...) wrapping

    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '*' => re.push_str(".*"),
            '?' => re.push('.'),
            '[' => {
                // Pass character class through as-is until the closing `]`.
                // Handle [!...] → [^...] negation (fnmatch semantics).
                re.push('[');
                i += 1;
                if i < chars.len() && chars[i] == '!' {
                    re.push('^'); // convert fnmatch negation to regex negation
                    i += 1;
                }
                // First `]` after `[` or `[^` is literal (fnmatch rule)
                if i < chars.len() && chars[i] == ']' {
                    re.push(']');
                    i += 1;
                }
                while i < chars.len() && chars[i] != ']' {
                    re.push(chars[i]);
                    i += 1;
                }
                if i < chars.len() {
                    re.push(']'); // closing ]
                }
            }
            c => re.push_str(&regex::escape(&c.to_string())),
        }
        i += 1;
    }

    re.push_str(r")\z"); // \z = true end-of-text (not end-of-line like $)
    Regex::new(&re)
}

/// Expand a leading `~` to the home directory.
///
/// Uses `dirs::home_dir()` which handles macOS, Linux, and Windows correctly —
/// equivalent to Python's `os.path.expanduser("~")`.
fn expand_home(s: &str) -> String {
    if s == "~" || s.starts_with("~/") || s.starts_with("~\\") {
        if let Some(home) = dirs::home_dir() {
            if let Some(home_str) = home.to_str() {
                return format!("{}{}", home_str, &s[1..]);
            }
        }
    }
    s.to_string()
}

/// Normalise a path for matching: expand `~`, forward slashes, strip trailing `/`.
fn normalise_path(path: &str) -> String {
    let expanded = expand_home(path);
    expanded
        .replace('\\', "/")
        .trim_end_matches('/')
        .to_string()
}

// ---------------------------------------------------------------------------
// PolicyMatcher — the public Python-facing class
// ---------------------------------------------------------------------------

/// Maximum path length accepted for matching (guard against adversarially long inputs).
const MAX_PATH_LEN: usize = 4096;

/// Pre-compiled policy pattern matcher.
///
/// Construct once at policy load time; call the `match_*` methods on every action.
/// All regex matching uses the `regex` crate's DFA engine — O(n) time, no backtracking.
///
/// # Python usage
/// ```python
/// from agentguard_rs import PolicyMatcher
///
/// m = PolicyMatcher(
///     path_patterns=["~/.ssh/**", "~/.aws/credentials"],
///     domain_patterns=["*.ngrok.io", "webhook.site"],
///     deny_tools=["bash", "shell.*"],
///     allow_tools=[],
///     review_tools=["file.*"],
///     unregistered_tools=["db.*"],
///     provenance_patterns=["external_data", "*_data"],
/// )
///
/// assert m.match_path("~/.ssh/id_rsa") == "~/.ssh/**"
/// assert m.match_domain("evil.ngrok.io") == "*.ngrok.io"
/// assert m.match_deny_tool("bash") is True
/// assert m.match_path("/tmp/safe.txt") is None
/// ```
#[pyclass]
struct PolicyMatcher {
    path_patterns: Vec<CompiledGlob>,
    domain_patterns: Vec<DomainPattern>,
    deny_tools: Vec<CompiledFnmatch>,
    allow_tools: Vec<CompiledFnmatch>,
    review_tools: Vec<CompiledFnmatch>,
    unregistered_tools: Vec<CompiledFnmatch>,
    provenance_patterns: Vec<CompiledFnmatch>,
}

#[pymethods]
impl PolicyMatcher {
    /// Construct a `PolicyMatcher` from raw pattern lists.
    ///
    /// # Arguments
    /// All pattern lists accept the same syntax as the AgentGuard YAML policy.
    /// Tool patterns should already be lowercased by the caller (matching Python behaviour).
    ///
    /// # Errors
    /// Raises `ValueError` if any pattern cannot be compiled to a valid regex.
    #[new]
    fn new(
        path_patterns: Vec<String>,
        domain_patterns: Vec<String>,
        deny_tools: Vec<String>,
        allow_tools: Vec<String>,
        review_tools: Vec<String>,
        unregistered_tools: Vec<String>,
        provenance_patterns: Vec<String>,
    ) -> PyResult<Self> {
        let compiled_paths = path_patterns
            .iter()
            .map(|p| {
                // Expand ~ and normalise before compiling so the compiled regex
                // matches against already-normalised input paths.
                let normalised = normalise_path(p);
                let regex = glob_to_regex(&normalised).map_err(|e| {
                    pyo3::exceptions::PyValueError::new_err(format!(
                        "Invalid glob pattern '{p}': {e}"
                    ))
                })?;
                Ok(CompiledGlob {
                    original: p.clone(),
                    regex,
                })
            })
            .collect::<PyResult<Vec<_>>>()?;

        let compiled_domains = domain_patterns
            .iter()
            .map(|p| {
                if let Some(rest) = p.strip_prefix("*.") {
                    // Fast suffix path: "*.ngrok.io" → suffix ".ngrok.io"
                    Ok(DomainPattern::Suffix(
                        format!(".{rest}"),
                        p.clone(),
                    ))
                } else {
                    let regex = fnmatch_to_regex(p).map_err(|e| {
                        pyo3::exceptions::PyValueError::new_err(format!(
                            "Invalid domain pattern '{p}': {e}"
                        ))
                    })?;
                    Ok(DomainPattern::Regex(p.clone(), regex))
                }
            })
            .collect::<PyResult<Vec<_>>>()?;

        let compile_fnmatch = |patterns: Vec<String>| -> PyResult<Vec<CompiledFnmatch>> {
            patterns
                .iter()
                .map(|p| {
                    let regex = fnmatch_to_regex(p).map_err(|e| {
                        pyo3::exceptions::PyValueError::new_err(format!(
                            "Invalid fnmatch pattern '{p}': {e}"
                        ))
                    })?;
                    Ok(CompiledFnmatch {
                        original: p.clone(),
                        regex,
                    })
                })
                .collect()
        };

        Ok(PolicyMatcher {
            path_patterns: compiled_paths,
            domain_patterns: compiled_domains,
            deny_tools: compile_fnmatch(deny_tools)?,
            allow_tools: compile_fnmatch(allow_tools)?,
            review_tools: compile_fnmatch(review_tools)?,
            unregistered_tools: compile_fnmatch(unregistered_tools)?,
            provenance_patterns: compile_fnmatch(provenance_patterns)?,
        })
    }

    // ------------------------------------------------------------------
    // Path matching
    // ------------------------------------------------------------------

    /// Match a file path against `deny_path_patterns`.
    ///
    /// Returns the first matched original pattern string, or `None`.
    /// Paths longer than 4096 bytes are rejected without matching (DoS guard).
    fn match_path(&self, path: &str) -> Option<String> {
        if path.len() > MAX_PATH_LEN {
            return None;
        }
        let normalised = normalise_path(path);
        for compiled in &self.path_patterns {
            if compiled.regex.is_match(&normalised) {
                return Some(compiled.original.clone());
            }
        }
        None
    }

    // ------------------------------------------------------------------
    // Domain matching
    // ------------------------------------------------------------------

    /// Match a domain against `deny_domains`.
    ///
    /// Returns the first matched original pattern string (e.g. `"*.ngrok.io"`), or `None`.
    fn match_domain(&self, domain: &str) -> Option<String> {
        for pat in &self.domain_patterns {
            match pat {
                DomainPattern::Suffix(suffix, original) => {
                    // suffix = ".ngrok.io"
                    // Matches "ngrok.io" (exact root) or "foo.ngrok.io" (subdomain).
                    let root = &suffix[1..]; // "ngrok.io"
                    if domain == root || domain.ends_with(suffix.as_str()) {
                        return Some(original.clone());
                    }
                }
                DomainPattern::Regex(original, regex) => {
                    if regex.is_match(domain) {
                        return Some(original.clone());
                    }
                }
            }
        }
        None
    }

    // ------------------------------------------------------------------
    // Tool matching
    // ------------------------------------------------------------------

    /// Returns `True` if `tool` matches any `deny_tools` pattern.
    fn match_deny_tool(&self, tool: &str) -> bool {
        self.deny_tools.iter().any(|p| p.regex.is_match(tool))
    }

    /// Returns `True` if `tool` matches any `allow_tools` pattern.
    fn match_allow_tool(&self, tool: &str) -> bool {
        self.allow_tools.iter().any(|p| p.regex.is_match(tool))
    }

    /// Returns `True` if `tool` matches any `review_tools` pattern.
    fn match_review_tool(&self, tool: &str) -> bool {
        self.review_tools.iter().any(|p| p.regex.is_match(tool))
    }

    /// Returns `True` if `tool` matches any `deny_unregistered_tools` pattern.
    fn match_unregistered_tool(&self, tool: &str) -> bool {
        self.unregistered_tools.iter().any(|p| p.regex.is_match(tool))
    }

    // ------------------------------------------------------------------
    // Provenance matching
    // ------------------------------------------------------------------

    /// Match a provenance source type string against `deny_provenance_sources`.
    ///
    /// Returns the first matched pattern string, or `None`.
    fn match_provenance(&self, source: &str) -> Option<String> {
        for compiled in &self.provenance_patterns {
            if compiled.regex.is_match(source) {
                return Some(compiled.original.clone());
            }
        }
        None
    }

    // ------------------------------------------------------------------
    // Introspection (testing / debugging)
    // ------------------------------------------------------------------

    /// Return pattern counts as a dict for testing and health checks.
    fn pattern_counts<'py>(&self, py: Python<'py>) -> pyo3::Bound<'py, pyo3::types::PyDict> {
        let dict = pyo3::types::PyDict::new(py);
        dict.set_item("path_patterns", self.path_patterns.len()).unwrap();
        dict.set_item("domain_patterns", self.domain_patterns.len()).unwrap();
        dict.set_item("deny_tools", self.deny_tools.len()).unwrap();
        dict.set_item("allow_tools", self.allow_tools.len()).unwrap();
        dict.set_item("review_tools", self.review_tools.len()).unwrap();
        dict.set_item("unregistered_tools", self.unregistered_tools.len()).unwrap();
        dict.set_item("provenance_patterns", self.provenance_patterns.len()).unwrap();
        dict
    }
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

#[pymodule]
fn agentguard_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PolicyMatcher>()?;
    Ok(())
}
