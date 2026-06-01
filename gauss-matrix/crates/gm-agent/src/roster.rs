// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! Multi-agent orchestration: a room's roster of agents (spec §IV).
//!
//! A single room may host several agents at once — an orchestrator delegating
//! to specialist workers, or independent assistants serving different teams.
//! Each is a distinct cross-signed principal with its **own** capability grant,
//! so admitting one never widens another's reach. An [`AgentRoster`] is the
//! per-room registry of those agents and their grants; the gateway dispatches an
//! inbound call to the calling agent's grant
//! ([`AgentGateway::handle_in_room`](crate::AgentGateway::handle_in_room)), and
//! every action is already attributed per agent in the audit chain.
//!
//! Orchestration adds one relation on top of independent agents: **delegation**,
//! where one agent asks another to act. The delegated call is still mediated
//! under the *worker's* grant (delegation cannot launder privilege), and the
//! delegating principal is recorded so the audit trail — and a replay — shows
//! the full chain
//! ([`AgentGateway::handle_delegated`](crate::AgentGateway::handle_delegated)).

use crate::capability::CapabilityGrant;
use crate::catalog::{DiscoverableTool, ToolCatalog};
use gm_util::AgentId;
use std::collections::BTreeMap;

/// A room's set of admitted agents, each mapped to its capability grant.
#[derive(Debug, Default, Clone)]
pub struct AgentRoster {
    grants: BTreeMap<String, CapabilityGrant>,
}

impl AgentRoster {
    /// An empty roster.
    pub fn new() -> Self {
        Self::default()
    }

    /// Admit an agent with its grant (builder-style). The grant's own `agent`
    /// field is the key, so a roster cannot disagree with a grant about who it
    /// is for.
    pub fn admit(mut self, grant: CapabilityGrant) -> Self {
        self.grants.insert(grant.agent.as_str().to_owned(), grant);
        self
    }

    /// Admit (or replace) an agent's grant in place.
    pub fn insert(&mut self, grant: CapabilityGrant) {
        self.grants.insert(grant.agent.as_str().to_owned(), grant);
    }

    /// Remove an agent from the roster, returning its grant if present.
    pub fn remove(&mut self, agent: &AgentId) -> Option<CapabilityGrant> {
        self.grants.remove(agent.as_str())
    }

    /// The grant for `agent`, if it is on the roster.
    pub fn grant_for(&self, agent: &AgentId) -> Option<&CapabilityGrant> {
        self.grants.get(agent.as_str())
    }

    /// Whether `agent` is on the roster.
    pub fn contains(&self, agent: &AgentId) -> bool {
        self.grants.contains_key(agent.as_str())
    }

    /// The agents on the roster, in identity order.
    pub fn agents(&self) -> impl Iterator<Item = &str> {
        self.grants.keys().map(String::as_str)
    }

    /// How many agents are on the roster.
    pub fn len(&self) -> usize {
        self.grants.len()
    }

    /// Whether the roster is empty.
    pub fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }

    /// The tools each agent on the roster may discover from `catalog`, keyed by
    /// agent — the union view an orchestrator uses to plan which agent can do
    /// what, each still scoped to that agent's own grant.
    pub fn discoverable_tools(
        &self,
        catalog: &ToolCatalog,
    ) -> BTreeMap<String, Vec<DiscoverableTool>> {
        self.grants
            .iter()
            .map(|(agent, grant)| (agent.clone(), catalog.list_for(grant)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::ActionClass;
    use crate::catalog::ToolSpec;
    use gm_util::RoomId;

    fn agent(id: &str) -> AgentId {
        AgentId::parse(id).unwrap()
    }

    fn room() -> RoomId {
        RoomId::parse("!r:gaussian.tech").unwrap()
    }

    fn roster() -> AgentRoster {
        AgentRoster::new()
            .admit(
                CapabilityGrant::deny_all(agent("@gauss_agent_orchestrator:gaussian.tech"))
                    .allow_room(room())
                    .allow_tool("search", ActionClass::Auto)
                    .allow_tool("delegate", ActionClass::Auto),
            )
            .admit(
                CapabilityGrant::deny_all(agent("@gauss_agent_mailer:gaussian.tech"))
                    .allow_room(room())
                    .allow_tool("send_email", ActionClass::Review),
            )
    }

    #[test]
    fn roster_holds_distinct_grants_per_agent() {
        let roster = roster();
        assert_eq!(roster.len(), 2);

        let orch = agent("@gauss_agent_orchestrator:gaussian.tech");
        let mailer = agent("@gauss_agent_mailer:gaussian.tech");
        // Each agent's grant is its own — orchestrator cannot send email,
        // mailer cannot search.
        assert!(roster.grant_for(&orch).unwrap().permits_tool("search"));
        assert!(!roster.grant_for(&orch).unwrap().permits_tool("send_email"));
        assert!(roster
            .grant_for(&mailer)
            .unwrap()
            .permits_tool("send_email"));
        assert!(!roster.grant_for(&mailer).unwrap().permits_tool("search"));
    }

    #[test]
    fn removing_an_agent_revokes_its_presence() {
        let mut roster = roster();
        let mailer = agent("@gauss_agent_mailer:gaussian.tech");
        assert!(roster.contains(&mailer));
        assert!(roster.remove(&mailer).is_some());
        assert!(!roster.contains(&mailer));
        assert_eq!(roster.len(), 1);
    }

    #[test]
    fn discoverable_tools_are_scoped_per_agent() {
        let catalog = ToolCatalog::new()
            .with_tool(ToolSpec::new("search", "Search", ActionClass::Auto))
            .with_tool(ToolSpec::new("send_email", "Email", ActionClass::Review))
            .with_tool(ToolSpec::new("delegate", "Delegate", ActionClass::Auto));
        let view = roster().discoverable_tools(&catalog);

        let orch: Vec<_> = view["@gauss_agent_orchestrator:gaussian.tech"]
            .iter()
            .map(|t| t.name.as_str())
            .collect();
        assert_eq!(orch, ["delegate", "search"]); // name-ordered, scoped to grant
        let mailer: Vec<_> = view["@gauss_agent_mailer:gaussian.tech"]
            .iter()
            .map(|t| t.name.as_str())
            .collect();
        assert_eq!(mailer, ["send_email"]);
    }
}
