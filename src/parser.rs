//! Parser for challenge/credentials.

use nom::{IResult, is_alphanumeric};
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

fn is_token(ch: u8) -> bool {
    match ch {
        b' ' | b'\t' | b'"' | b',' | b'=' => false,
        _ => true
    }
}

fn is_equal(ch: u8) -> bool {
    ch == b'='
}

fn is_space(ch: u8) -> bool {
    ch == b' '
}

fn is_whitespace(ch: u8) -> bool {
    ch == b' ' || ch == b'\t'
}

fn is_token68(ch: u8) -> bool {
    match ch {
        b'-' | b'.' | b'_' | b'~' | b'+' | b'/' => true,
        _ => is_alphanumeric(ch)
    }
}

named!(parse_token,
    take_while1!(is_token)
);

// TODO return Cow in case string contains escaped chars
named!(quoted_string,
    take_while1!(is_token)
);

named!(parse_param<()>,
    do_parse!(
        key: take_while1!(is_token) >>
        take_while!(is_whitespace) >> // bad whitespace
        char!('=') >>
        take_while!(is_whitespace) >> // bad whitespace
        value: alt!(take_while1!(is_token) | quoted_string) >>
        ({

        })
    )
);

named!(parse_map<Option<Params>>,
    do_parse!(
        param: alt!(
            map!(char!(b','), |_| None) |
            map!(parse_param, |param| Some(param))
        ) >>
        advance >>
        rest: many0!(parse_param) >>
        ({
            param.map_or(None, |()| Some(Params::Map(vec![])))
        })
    )
);

named!(parse_map_opt<Option<Params>>,
    do_parse!(params: opt!(parse_map) >> (params.unwrap_or(None)))
);

named!(parse_token68<Option<Params>>,
    do_parse!(
        name: map_res!(preceded!(take_while!(is_token68), take_while!(is_equal)), str::from_utf8) >>
        ({
            Some(Params::Base64(name.into()))
        })
    )
);

named!(parse_params<Option<Params>>,
    do_parse!(
        take_while1!(is_space) >>
        // token68 can be a prefix of auth-param:
        // token68: abcd=
        // auth-param: abcd=efgh
        // so we test the longest, map_opt, first:
        params: alt!(parse_map_opt | parse_token68) >>
        ({
            params
        })
    )
);

named!(parse_scheme<Scheme>,
    do_parse!(
        advance >>
        scheme: map_res!(parse_token, str::from_utf8) >>
        params: opt!(parse_params) >>
        ({
            new_challenge(scheme, params.unwrap_or(None))
        })
    )
);

named!(pub parse_authentication<Authentication>,
    map!(many0!(parse_scheme), |challenges| new_authentication(challenges))
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
