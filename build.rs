extern crate skeptic;

fn main() {
  // generates doc tests for `README.md`.
  #[cfg(feature = "serialize")]
  skeptic::generate_doc_tests(&["README.md"]);
}
