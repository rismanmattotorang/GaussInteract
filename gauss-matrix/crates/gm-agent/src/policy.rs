// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! Declarative policy engine (spec §IV.C).
//!
//! A [`CapabilityGrant`](crate::capability::CapabilityGrant) answers *what an
//! agent may use at all* — its tools, rooms and per-tool `auto`/`review`/`
//! forbidden` class. A [`PolicySet`] layers *conditional* rules on top: a
//! first-match-wins firewall of allow / require-review / deny rules that can
//! match on the tool, the room, and a substring of the call's arguments. Like a
//! grant it is room state (`m.gauss.agent.policy`) — visible, versioned,
//! federated and revocable.
//!
//! **Least privilege is preserved by construction:** policy can only *tighten*,
//! never widen. A tool the grant forbids stays forbidden whatever the policy
//! says; a policy can downgrade `auto` to `review` or to a denial, but it can
//! never upgrade a `review` tool to `auto` or admit a tool the grant withholds
//! (see [`refine`]).

use crate::capability::ActionClass;
use crate::events::{ReflectedEvent, Value, TYPE_POLICY};
use std::collections::BTreeMap;
use std::fmt;

/// What a policy rule does when it matches a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// Impose no extra restriction (the grant's classification stands).
    Allow,
    /// Force the call through human review, even if the grant auto-approves it.
    RequireReview,
    /// Refuse the call outright.
    Deny,
}

impl Effect {
    /// The wire string for this effect.
    pub fn as_str(&self) -> &'static str {
        match self {
            Effect::Allow => "allow",
            Effect::RequireReview => "review",
            Effect::Deny => "deny",
        }
    }

    /// Parse an effect from its wire string.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "allow" => Some(Effect::Allow),
            "review" => Some(Effect::RequireReview),
            "deny" => Some(Effect::Deny),
            _ => None,
        }
    }
}

/// Refine a grant's classification with a policy effect. Policy can only
/// tighten: a forbidden tool stays forbidden, and an effect never widens access
/// (`auto` may become `review` or `forbidden`, but `review` never becomes
/// `auto`).
pub fn refine(class: ActionClass, effect: Effect) -> ActionClass {
    match class {
        // The grant withholds the tool entirely — policy cannot grant it.
        ActionClass::Forbidden => ActionClass::Forbidden,
        _ => match effect {
            Effect::Deny => ActionClass::Forbidden,
            Effect::RequireReview => ActionClass::Review,
            Effect::Allow => class,
        },
    }
}

/// One conditional rule. A `None` matcher matches anything; `args_contains`
/// matches when the call's argument summary contains the given substring. The
/// empty string as a `tool`/`room` matcher (on the wire) means "any".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRule {
    /// What to do when this rule matches.
    pub effect: Effect,
    /// Match only this tool (None = any tool).
    pub tool: Option<String>,
    /// Match only this room (None = any room).
    pub room: Option<String>,
    /// Match only when the argument summary contains this substring (None = any).
    pub args_contains: Option<String>,
}

impl PolicyRule {
    /// A rule with the given effect matching any call; narrow it with the
    /// builder methods below.
    pub fn new(effect: Effect) -> Self {
        Self {
            effect,
            tool: None,
            room: None,
            args_contains: None,
        }
    }

    /// Restrict the rule to a specific tool (builder-style).
    pub fn for_tool(mut self, tool: impl Into<String>) -> Self {
        self.tool = Some(tool.into());
        self
    }

    /// Restrict the rule to a specific room (builder-style).
    pub fn in_room(mut self, room: impl Into<String>) -> Self {
        self.room = Some(room.into());
        self
    }

    /// Restrict the rule to calls whose arguments contain `needle` (builder).
    pub fn when_args_contain(mut self, needle: impl Into<String>) -> Self {
        self.args_contains = Some(needle.into());
        self
    }

    /// Whether this rule matches a call.
    fn matches(&self, tool: &str, room: &str, args_summary: &str) -> bool {
        self.tool.as_deref().map(|t| t == tool).unwrap_or(true)
            && self.room.as_deref().map(|r| r == room).unwrap_or(true)
            && self
                .args_contains
                .as_deref()
                .map(|n| args_summary.contains(n))
                .unwrap_or(true)
    }
}

/// An ordered set of policy rules with a default effect. The first rule that
/// matches a call decides its effect; if none match, `default_effect` applies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySet {
    /// The rules, evaluated in order (first match wins).
    pub rules: Vec<PolicyRule>,
    /// The effect when no rule matches.
    pub default_effect: Effect,
}

impl PolicySet {
    /// A permissive policy (no rules; everything the grant allows passes).
    pub fn allow_by_default() -> Self {
        Self {
            rules: Vec::new(),
            default_effect: Effect::Allow,
        }
    }

    /// A policy that defaults to `default_effect` with the given rules.
    pub fn new(default_effect: Effect, rules: Vec<PolicyRule>) -> Self {
        Self {
            rules,
            default_effect,
        }
    }

    /// Append a rule (builder-style).
    pub fn with_rule(mut self, rule: PolicyRule) -> Self {
        self.rules.push(rule);
        self
    }

    /// The effect for a call: the first matching rule's effect, else the
    /// default.
    pub fn evaluate(&self, tool: &str, room: &str, args_summary: &str) -> Effect {
        self.rules
            .iter()
            .find(|r| r.matches(tool, room, args_summary))
            .map(|r| r.effect)
            .unwrap_or(self.default_effect)
    }

    /// Serialise to `m.gauss.agent.policy` event content (room state). Each rule
    /// is a 4-element list `[effect, tool, room, args_contains]`; an absent
    /// matcher is the empty string.
    pub fn to_content(&self) -> BTreeMap<String, Value> {
        let mut content = BTreeMap::new();
        content.insert(
            "default_effect".into(),
            Value::Str(self.default_effect.as_str().to_owned()),
        );
        content.insert(
            "rules".into(),
            Value::List(
                self.rules
                    .iter()
                    .map(|r| {
                        Value::List(vec![
                            Value::Str(r.effect.as_str().to_owned()),
                            Value::Str(r.tool.clone().unwrap_or_default()),
                            Value::Str(r.room.clone().unwrap_or_default()),
                            Value::Str(r.args_contains.clone().unwrap_or_default()),
                        ])
                    })
                    .collect(),
            ),
        );
        content
    }

    /// The policy as a `m.gauss.agent.policy` state event payload.
    pub fn to_event(&self) -> ReflectedEvent {
        ReflectedEvent {
            event_type: TYPE_POLICY,
            content: self.to_content(),
        }
    }

    /// Decode from (untrusted, possibly federated) event content, re-validating
    /// every effect string.
    pub fn from_content(content: &BTreeMap<String, Value>) -> Result<Self, PolicyError> {
        let default_effect = content
            .get("default_effect")
            .ok_or(PolicyError::MissingField("default_effect"))?
            .as_str()
            .and_then(Effect::parse)
            .ok_or(PolicyError::InvalidField("default_effect"))?;

        let mut rules = Vec::new();
        let rule_values = content
            .get("rules")
            .ok_or(PolicyError::MissingField("rules"))?
            .as_list()
            .ok_or(PolicyError::InvalidField("rules"))?;
        for value in rule_values {
            let parts = value
                .as_list()
                .filter(|p| p.len() == 4)
                .ok_or(PolicyError::InvalidField("rules"))?;
            let effect = parts[0]
                .as_str()
                .and_then(Effect::parse)
                .ok_or(PolicyError::InvalidField("rules"))?;
            let opt = |i: usize| -> Result<Option<String>, PolicyError> {
                let s = parts[i]
                    .as_str()
                    .ok_or(PolicyError::InvalidField("rules"))?;
                Ok(if s.is_empty() {
                    None
                } else {
                    Some(s.to_owned())
                })
            };
            rules.push(PolicyRule {
                effect,
                tool: opt(1)?,
                room: opt(2)?,
                args_contains: opt(3)?,
            });
        }
        Ok(Self {
            rules,
            default_effect,
        })
    }
}

/// Error decoding a [`PolicySet`] from event content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// A required field was absent.
    MissingField(&'static str),
    /// A field was present but malformed.
    InvalidField(&'static str),
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyError::MissingField(k) => write!(f, "missing policy field: {k}"),
            PolicyError::InvalidField(k) => write!(f, "invalid policy field: {k}"),
        }
    }
}

impl std::error::Error for PolicyError {}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOM: &str = "!room:gaussian.tech";

    #[test]
    fn first_matching_rule_wins_else_default() {
        let policy = PolicySet::new(Effect::Allow, vec![])
            .with_rule(
                PolicyRule::new(Effect::Deny)
                    .for_tool("send_email")
                    .when_args_contain("@external"),
            )
            .with_rule(PolicyRule::new(Effect::RequireReview).for_tool("send_email"));

        // Matches the first rule (external recipient) -> deny.
        assert_eq!(
            policy.evaluate("send_email", ROOM, "to=@external:evil.tld"),
            Effect::Deny
        );
        // Falls through to the second rule -> review.
        assert_eq!(
            policy.evaluate("send_email", ROOM, "to=@bob:gaussian.tech"),
            Effect::RequireReview
        );
        // No rule matches -> default allow.
        assert_eq!(policy.evaluate("search", ROOM, "q=foo"), Effect::Allow);
    }

    #[test]
    fn refine_only_tightens_never_widens() {
        // Forbidden stays forbidden regardless of effect.
        assert_eq!(
            refine(ActionClass::Forbidden, Effect::Allow),
            ActionClass::Forbidden
        );
        // Auto can be tightened to review or denied, or left alone.
        assert_eq!(refine(ActionClass::Auto, Effect::Allow), ActionClass::Auto);
        assert_eq!(
            refine(ActionClass::Auto, Effect::RequireReview),
            ActionClass::Review
        );
        assert_eq!(
            refine(ActionClass::Auto, Effect::Deny),
            ActionClass::Forbidden
        );
        // Review is never downgraded to auto by an Allow effect.
        assert_eq!(
            refine(ActionClass::Review, Effect::Allow),
            ActionClass::Review
        );
        assert_eq!(
            refine(ActionClass::Review, Effect::Deny),
            ActionClass::Forbidden
        );
    }

    #[test]
    fn room_scoped_rule_matches_only_its_room() {
        let policy = PolicySet::allow_by_default()
            .with_rule(PolicyRule::new(Effect::Deny).in_room("!prod:gaussian.tech"));
        assert_eq!(
            policy.evaluate("deploy", "!prod:gaussian.tech", ""),
            Effect::Deny
        );
        assert_eq!(
            policy.evaluate("deploy", "!staging:gaussian.tech", ""),
            Effect::Allow
        );
    }

    #[test]
    fn policy_round_trips_through_event_content() {
        let policy = PolicySet::new(Effect::Allow, vec![])
            .with_rule(
                PolicyRule::new(Effect::Deny)
                    .for_tool("send_email")
                    .when_args_contain("@external"),
            )
            .with_rule(PolicyRule::new(Effect::RequireReview).in_room(ROOM));

        let restored = PolicySet::from_content(&policy.to_content()).unwrap();
        assert_eq!(restored, policy);
        assert_eq!(policy.to_event().event_type, "m.gauss.agent.policy");
    }

    #[test]
    fn decoding_rejects_an_unknown_effect() {
        let mut content = PolicySet::allow_by_default().to_content();
        content.insert("default_effect".into(), Value::Str("sudo".into()));
        assert_eq!(
            PolicySet::from_content(&content),
            Err(PolicyError::InvalidField("default_effect"))
        );
    }

    #[test]
    fn decoding_missing_rules_field_fails() {
        let mut content = PolicySet::allow_by_default().to_content();
        content.remove("rules");
        assert_eq!(
            PolicySet::from_content(&content),
            Err(PolicyError::MissingField("rules"))
        );
    }
}
