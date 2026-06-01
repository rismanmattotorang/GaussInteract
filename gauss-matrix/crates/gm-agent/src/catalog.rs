// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! MCP tool catalog and capability-scoped tool discovery (spec §IV.B).
//!
//! MCP connects agents to *tools and data*. The outbound half (mediating tool
//! *calls*) is in the gateway; this is the discovery half: a [`ToolCatalog`] of
//! the tools a deployment offers, filtered per agent so an agent only ever
//! *sees* the tools its capability grant permits — and sees each one tagged with
//! how the grant classifies it (`auto` / `review`). An agent can therefore
//! enumerate exactly what it may do, no more, which is the inbound mirror of the
//! gateway's least-privilege mediation.

use crate::capability::{ActionClass, CapabilityGrant};
use std::collections::BTreeMap;

/// A tool the deployment offers to agents over MCP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolSpec {
    /// The tool's stable name (what a `tool_call` names).
    pub name: String,
    /// A human-readable description shown to the model/operator.
    pub description: String,
    /// The catalog's *advisory* default classification for this tool. The
    /// capability grant is authoritative; this is the recommended posture a
    /// grant author starts from (e.g. high-impact tools advise `review`).
    pub advised_class: ActionClass,
}

impl ToolSpec {
    /// Construct a tool spec.
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        advised_class: ActionClass,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            advised_class,
        }
    }
}

/// A tool an agent may discover, with the classification its grant assigns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoverableTool {
    /// The tool name.
    pub name: String,
    /// The tool description.
    pub description: String,
    /// How *this agent's grant* classifies the tool (`auto` / `review`).
    pub class: ActionClass,
}

/// The catalog of tools a deployment exposes to agents.
#[derive(Debug, Default)]
pub struct ToolCatalog {
    tools: BTreeMap<String, ToolSpec>,
}

impl ToolCatalog {
    /// An empty catalog.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register (or replace) a tool. Builder-style.
    pub fn with_tool(mut self, spec: ToolSpec) -> Self {
        self.tools.insert(spec.name.clone(), spec);
        self
    }

    /// Look up a tool spec by name.
    pub fn get(&self, name: &str) -> Option<&ToolSpec> {
        self.tools.get(name)
    }

    /// Every tool in the catalog (name-ordered).
    pub fn all(&self) -> impl Iterator<Item = &ToolSpec> {
        self.tools.values()
    }

    /// The tools `grant` may discover: those in the catalog the grant permits,
    /// each tagged with the grant's classification (not the catalog's advice).
    pub fn list_for(&self, grant: &CapabilityGrant) -> Vec<DiscoverableTool> {
        self.tools
            .values()
            .filter_map(|spec| {
                grant.tool_class(&spec.name).map(|class| DiscoverableTool {
                    name: spec.name.clone(),
                    description: spec.description.clone(),
                    class,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gm_util::{AgentId, RoomId};

    fn catalog() -> ToolCatalog {
        ToolCatalog::new()
            .with_tool(ToolSpec::new(
                "search_kb",
                "Search the knowledge base",
                ActionClass::Auto,
            ))
            .with_tool(ToolSpec::new(
                "send_email",
                "Send an external email",
                ActionClass::Review,
            ))
            .with_tool(ToolSpec::new(
                "delete_account",
                "Delete a user",
                ActionClass::Forbidden,
            ))
    }

    #[test]
    fn discovery_is_scoped_to_the_grant_and_uses_its_classification() {
        let grant =
            CapabilityGrant::deny_all(AgentId::parse("@gauss_agent_x:gaussian.tech").unwrap())
                .allow_room(RoomId::parse("!r:gaussian.tech").unwrap())
                .allow_tool("search_kb", ActionClass::Auto)
                .allow_tool("send_email", ActionClass::Review);

        let discoverable = catalog().list_for(&grant);
        let names: Vec<_> = discoverable.iter().map(|t| t.name.as_str()).collect();
        // delete_account is in the catalog but not granted -> not discoverable.
        assert_eq!(names, ["search_kb", "send_email"]);
        let email = discoverable
            .iter()
            .find(|t| t.name == "send_email")
            .unwrap();
        assert_eq!(email.class, ActionClass::Review);
    }

    #[test]
    fn an_empty_grant_discovers_nothing() {
        let grant =
            CapabilityGrant::deny_all(AgentId::parse("@gauss_agent_x:gaussian.tech").unwrap());
        assert!(catalog().list_for(&grant).is_empty());
    }
}
