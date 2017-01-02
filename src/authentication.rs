//! This module defines structures for authentication.

use std::borrow::Cow;

#[derive(Debug)]
pub struct Scheme<'a> {
    name: Cow<'a, str>,
    params: Option<Params<'a>>
}

#[derive(Debug)]
pub enum Params<'a> {
    Base64(Cow<'a, str>),
    Map(Vec<(Cow<'a, str>, Cow<'a, str>)>)
}

impl<'a> Scheme<'a> {
    pub fn name(&'a self) -> &'a str {
        &self.name
    }

    pub fn params(&self) -> Option<&Params<'a>> {
        self.params.as_ref()
    }
}

pub struct Authentication<'a> {
    challenges: Vec<Scheme<'a>>
}

pub fn new_challenge<'a>(name: &'a str, params: Option<Params<'a>>) -> Scheme<'a> {
    Scheme {
        name: name.into(),
        params: params
    }
}

pub fn new_authentication(challenges: Vec<Scheme>) -> Authentication {
    Authentication {
        challenges: challenges
    }
}

pub struct Authorization<'a> {
    credential: Scheme<'a>
}
