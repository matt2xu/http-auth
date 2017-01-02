//! Parser for challenge/credentials.

use nom::{IResult};
use nom::IResult::{Done, Error};

use super::{Scheme, Params, Authentication};
use authentication::{new_authentication, new_challenge};

use std::str;

fn can_skip(c: u8) -> bool {
    c == b' ' || c == b'\t' || c == b','
}

named!(advance,
    take_while!(can_skip)
);

fn is_ident(ch: u8) -> bool {
    match ch { b' ' | b'\t' | b'"' | b',' => true, _ => false }
}

fn is_equal(ch: u8) -> bool {
    ch == b'='
}

named!(parse_name,
    preceded!(take_while!(is_ident), take_while!(is_equal))
);

// TODO parse params
named!(parse_params<Params>,
    do_parse!(
        advance >>
        ({
            Params::Base64("toto".into())
        })
    )
);

named!(parse_scheme<Scheme>,
    do_parse!(
        advance >>
        scheme: map_res!(parse_name, str::from_utf8) >>
        params: opt!(parse_params) >>
        ({
            new_challenge(scheme, params)
        })
    )
);

named!(pub parse_authentication<Authentication>,
    do_parse!(
        challenges: many0!(parse_scheme) >>
        ({
            new_authentication(vec![])
        })
    )
);

#[cfg(test)]
mod tests {
    use super::parse_authentication;

    #[test]
    fn test_response() {
        let result = parse_authentication(b"  ,,,  ,   Digest a=b   , ,,  ,c  =  d,Basic zzzzz==   ,   Digest x=y,z=w");

        // test parsing
        assert!(result.is_done());
        let (body, res) = result.unwrap();
        assert_eq!(body, &b"12345"[..]);
    }
}
