//! This module defines structures for authentication.

use std::borrow::Cow;

#[derive(Debug)]
pub struct Challenge<'a> {
    scheme: Cow<'a, str>,
    info: Option<ChallengeInfo<'a>>
}

#[derive(Debug)]
pub enum ChallengeInfo<'a> {
    Base64(Cow<'a, str>),
    Params(Vec<(Cow<'a, str>, Cow<'a, str>)>)
}

impl<'a> Challenge<'a> {
    pub fn scheme(&'a self) -> &'a str {
        &self.scheme
    }

    pub fn info(&self) -> Option<&ChallengeInfo<'a>> {
        self.info.as_ref()
    }
}

pub struct Authentication<'a> {
    challenges: Vec<Challenge<'a>>
}

pub fn new_challenge<'a>(scheme: &'a str, info: Option<ChallengeInfo<'a>>) -> Challenge<'a> {
    Challenge {
        scheme: scheme.into(),
        info: info
    }
}

pub fn new_authentication(challenges: Vec<Challenge>) -> Authentication {
    Authentication {
        challenges: challenges
    }
}

pub struct Authorization<'a> {
    credential: Challenge<'a>
}
