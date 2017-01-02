//! Support for HTTP Authentication [RFC 7235](https://tools.ietf.org/html/rfc7235).
//!
//! 

#[macro_use]
extern crate nom;

mod parser;
mod authentication;

pub use authentication::{Scheme, Params, Authentication, Authorization};

pub use parser::parse_authentication;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
