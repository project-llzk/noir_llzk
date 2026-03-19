mod and_tests;
mod rangecheck_tests;
mod xor_tests;

/// Counts occurrences of `needle` in `haystack`.
fn count_occurrences(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}
