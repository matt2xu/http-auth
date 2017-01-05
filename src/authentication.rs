//! This module defines structures for authentication.

use std::borrow::Cow;

#[derive(Debug, PartialEq, Eq)]
pub struct Scheme<'a> {
    name: Cow<'a, str>,
    params: Option<Params<'a>>
}

#[derive(Debug, PartialEq, Eq)]
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

#[derive(Debug, PartialEq, Eq)]
pub struct Authentication<'a> {
    pub challenges: Vec<Scheme<'a>>
}

pub fn new_scheme<'a>(name: Cow<'a, str>, params: Option<Params<'a>>) -> Scheme<'a> {
    Scheme {
        name: name,
        params: params
    }
}

pub fn new_authentication(challenges: Vec<Scheme>) -> Authentication {
    Authentication {
        challenges: challenges
    }
}

pub struct Authorization<'a> {
    pub credentials: Scheme<'a>
}
