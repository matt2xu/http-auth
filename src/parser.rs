//! Parser for challenge/credentials.

use nom::{IResult, anychar, is_alphanumeric};

use super::{Scheme, Params, Authentication};
use authentication::{new_authentication, new_scheme};

use std::borrow::Cow;
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

named!(token<&str>,
    map_res!(take_while1!(is_token), str::from_utf8)
);

fn parse_token<'a>(input: &'a [u8]) -> IResult<&'a [u8], Cow<'a, str>> {
    token(input).map(|s| s.into())
}

named!(raw_quoted_string<&str>,
    delimited!(
        char!('\"'),
        map_res!(escaped!(is_not!(&b"\"\\"[..]), '\\', call!(anychar)), str::from_utf8),
        char!('\"')
    )
);

fn quoted_string<'a>(input: &'a [u8]) -> IResult<&'a [u8], Cow<'a, str>> {
    raw_quoted_string(input).map(|qstr| {
        if qstr.find(|ch| ch == '\\').is_some() {
            let mut res = String::with_capacity(qstr.len());
            let mut it = qstr.chars();
            while let Some(mut ch) = it.next() {
                if ch == '\\' {
                    ch = it.next().unwrap(); // guaranteed by escaped macro
                }
                res.push(ch);
            }
            res.into()
        } else {
            qstr.into()
        }
    })
}

fn parse_param<'a>(input: &'a [u8]) -> IResult<&'a [u8], (Cow<'a, str>, Cow<'a, str>)> {
    do_parse!(input,
        advance >>
        key: parse_token >>
        take_while!(is_whitespace) >> // bad whitespace
        char!('=') >>
        take_while!(is_whitespace) >> // bad whitespace
        value: alt!(parse_token | quoted_string) >>
        ({
            (key, value)
        })
    )
}

named!(parse_map<Option<Params>>,
    do_parse!(
        params: many1!(parse_param) >>
        ({
            println!("got params!");
            Some(Params::Map(params))
        })
    )
);

fn token68(input: &[u8]) -> IResult<&[u8], &[u8]> {
    do_parse!(input,
        first: take_while1!(is_token68) >>
        second: take_while!(is_equal) >>
        ({
            // concatenate
            &input[0 .. first.len() + second.len()]
        })
    )
}

named!(parse_token68<Option<Params>>,
    do_parse!(
        name: opt!(map_res!(token68, str::from_utf8)) >>
        ({
            name.map(|name| Params::Base64(name.into()))
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
        params: alt_complete!(parse_map | parse_token68) >>
        ({
            println!("got params: {:?}", params);
            params
        })
    )
);

named!(parse_scheme<Scheme>,
    do_parse!(
        advance >>
        scheme: parse_token >>
        params: opt!(parse_params) >>
        ({
            new_scheme(scheme, params.unwrap_or(None))
        })
    )
);

named!(pub parse_authentication<Authentication>,
    map!(many0!(parse_scheme), |challenges| new_authentication(challenges))
);

#[cfg(test)]
mod tests {
    use super::parse_authentication;
    use authentication::{new_authentication, new_scheme, Params};

    #[test]
    fn test_scheme_only() {
        let auth_simple = new_authentication(vec![new_scheme("a-scheme".into(), None)]);

        let result = parse_authentication(b"a-scheme");
        assert!(result.is_done());
        let (remaining, auth) = result.unwrap();
        assert_eq!(remaining, &b""[..]);
        assert_eq!(auth, auth_simple);

        let result = parse_authentication(b", a-scheme  ");
        assert!(result.is_done());
        let (remaining, auth) = result.unwrap();
        assert_eq!(remaining, &b""[..]);
        assert_eq!(auth, auth_simple);

        let two_schemes = new_authentication(vec![
            new_scheme("scheme-a".into(), None),
            new_scheme("scheme-b".into(), None)
        ]);

        let result = parse_authentication(b"scheme-a  ,  scheme-b");
        println!("{:?}", result);
        assert!(result.is_done());
        let (remaining, auth) = result.unwrap();
        assert_eq!(remaining, &b""[..]);
        assert_eq!(auth, two_schemes);
    }

    #[test]
    fn test_token68() {
        let auth_basic = new_authentication(vec![
            new_scheme("Basic".into(), Some(Params::Base64("abcdefgh".into())))
        ]);

        let result = parse_authentication(b"Basic abcdefgh");
        let (remaining, auth) = result.unwrap();
        assert_eq!(remaining, &b""[..]);
        assert_eq!(auth, auth_basic);

        let auth_basic1 = new_authentication(vec![
            new_scheme("Basic".into(), Some(Params::Base64("abcdefgh=".into())))
        ]);

        let result = parse_authentication(b"Basic abcdefgh=");
        let (remaining, auth) = result.unwrap();
        assert_eq!(remaining, &b""[..]);
        assert_eq!(auth, auth_basic1);

        let auth_basic2 = new_authentication(vec![
            new_scheme("Basic".into(), Some(Params::Base64("abcdefgh==".into())))
        ]);

        let result = parse_authentication(b"Basic abcdefgh==");
        let (remaining, auth) = result.unwrap();
        assert_eq!(remaining, &b""[..]);
        assert_eq!(auth, auth_basic2);

        let two_basic = new_authentication(vec![
            new_scheme("Basic".into(), Some(Params::Base64("abcdefgh=".into()))),
            new_scheme("Basic".into(), Some(Params::Base64("abcdefgh==".into())))
        ]);

        let result = parse_authentication(b"Basic abcdefgh= , Basic abcdefgh==");
        let (remaining, auth) = result.unwrap();
        assert_eq!(remaining, &b""[..]);
        assert_eq!(auth, two_basic);
    }

    #[test]
    fn test_params() {
        let auth_digest = new_authentication(vec![
            new_scheme("Digest".into(), Some(Params::Map(vec![
                ("realm".into(), "example.com".into()),
                ("username".into(), "sally".into())
            ])))
        ]);

        let result = parse_authentication(b"Digest realm=example.com, username=sally");
        let (remaining, auth) = result.unwrap();
        assert_eq!(remaining, &b""[..]);
        assert_eq!(auth, auth_digest);
    }

    #[test]
    fn test_two() {
        let auth_two = new_authentication(vec![
            new_scheme("Digest".into(), Some(Params::Map(vec![
                ("realm".into(), "example.com".into()),
                ("username".into(), "sally".into())
            ]))),

            new_scheme("Basic".into(), Some(Params::Base64("abcdefgh==".into())))
        ]);

        let result = parse_authentication(b"Digest realm=\"example.com\", username=sally,Basic abcdefgh==");
        let (remaining, auth) = result.unwrap();
        assert_eq!(remaining, &b""[..]);
        assert_eq!(auth, auth_two);
    }
}
