// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! A worked end-to-end pass over the full agentic surface (GaussInteract-SPECS
//! §IV, §VIII), exercised purely through the public API: provision an agent,
//! grant it via room-state content, expose scoped resources, mediate auto /
//! review / forbidden / unmanaged tool calls, then verify the tamper-evident
//! audit chain, stream it to a SIEM, and read back the metrics.

use gm_agent::appservice::{AgentNamespace, AppserviceRegistration};
use gm_agent::capability::{ActionClass, CapabilityGrant};
use gm_agent::mcp::{EchoExecutor, ToolCall};
use gm_agent::resources::{MapRoomContext, Message};
use gm_agent::{AgentGateway, GatewayError, Outcome};
use gm_util::RoomId;

#[test]
fn agentic_loop_end_to_end() {
    // 1. PROVISION — an Application Service owns an exclusive agent namespace
    //    and mints a cross-signed agent identity within it (§IV.A).
    let namespace = AgentNamespace::new("gaussian.tech", "gauss_agent_");
    let registration = AppserviceRegistration::new("gauss-agents", "gauss", namespace)
        .with_tokens("as-secret", "hs-secret")
        .with_url("https://gateway.gaussian.tech");
    let agent = registration.namespace.mint("assistant").unwrap();
    let room = RoomId::parse("!ops:gaussian.tech").unwrap();

    // 2. GRANT AS ROOM STATE — author a least-privilege grant, serialise it to
    //    m.gauss.agent.capability content, and decode it back, exactly as it
    //    would round-trip when stored as (federated) room state (§IV.C).
    let authored = CapabilityGrant::deny_all(agent.clone())
        .allow_room(room.clone())
        .allow_tool("search_kb", ActionClass::Auto)
        .allow_tool("send_email", ActionClass::Review)
        .with_rate_limit(30);
    let grant = CapabilityGrant::from_content(&authored.to_content()).unwrap();
    assert_eq!(grant, authored);

    let mut gw = AgentGateway::new();
    let mut exec = EchoExecutor;

    // 3. SCOPED READS — the agent sees only its granted room (§IV.B inbound).
    let ctx = MapRoomContext::default().with_messages(
        &room,
        vec![Message::new(
            "@alice:gaussian.tech",
            "what's our Q3 revenue?",
        )],
    );
    let resources = gw.list_resources(&grant);
    assert_eq!(resources.len(), 1);
    let contents = gw.read_resource(&grant, &resources[0].uri, &ctx).unwrap();
    assert!(contents.text.contains("Q3 revenue"));
    let secret_uri = format!("gauss://room/{}", "!secret:gaussian.tech");
    assert!(matches!(
        gw.read_resource(&grant, &secret_uri, &ctx),
        Err(GatewayError::ResourceAccessDenied(_)),
    ));

    // 4. AUTO write — executed immediately, reflecting tool_call + tool_result.
    let auto = gw.handle_managed(
        &registration,
        &grant,
        ToolCall::parse(agent.as_str(), room.as_str(), "search_kb", "q=revenue").unwrap(),
        &mut exec,
    );
    match auto {
        Outcome::Executed { events } => {
            assert_eq!(events.len(), 2);
            assert_eq!(events[0].event_type, "m.gauss.agent.tool_call");
            assert_eq!(events[1].event_type, "m.gauss.agent.tool_result");
        }
        other => panic!("expected Executed, got {other:?}"),
    }

    // 5. REVIEW write — held for a human, then approved and executed (§IV.C).
    let review = gw.handle_managed(
        &registration,
        &grant,
        ToolCall::parse(agent.as_str(), room.as_str(), "send_email", "to=finance").unwrap(),
        &mut exec,
    );
    let request_id = match review {
        Outcome::AwaitingApproval { request_id, event } => {
            assert_eq!(event.event_type, "m.gauss.agent.tool_call");
            request_id
        }
        other => panic!("expected AwaitingApproval, got {other:?}"),
    };
    assert_eq!(gw.pending().len(), 1);
    assert!(matches!(
        gw.resolve(request_id, true, "@boss:gaussian.tech", &mut exec),
        Ok(Outcome::Executed { .. }),
    ));
    assert!(gw.pending().is_empty());

    // 6. FORBIDDEN write — refused by capability scope before entering the room.
    assert!(matches!(
        gw.handle_managed(
            &registration,
            &grant,
            ToolCall::parse(agent.as_str(), room.as_str(), "delete_account", "all").unwrap(),
            &mut exec,
        ),
        Outcome::Denied { .. },
    ));

    // 7. UNMANAGED identity — a principal the AS never provisioned is refused.
    assert!(matches!(
        gw.handle_managed(
            &registration,
            &grant,
            ToolCall::parse("@mallory:gaussian.tech", room.as_str(), "search_kb", "q").unwrap(),
            &mut exec,
        ),
        Outcome::Denied { .. },
    ));

    // 8. AUDIT — the chain verifies and streams to a SIEM as structured records.
    assert_eq!(gw.verify_audit(), Ok(()));
    let records = gw.audit_records();
    assert!(records.len() >= 8);
    for pair in records.windows(2) {
        assert_eq!(pair[1].prev_hash, pair[0].hash, "audit chain must link");
    }
    assert!(records.iter().any(|r| r.action.starts_with("executed:")));
    assert!(records
        .iter()
        .any(|r| r.action.starts_with("resource_read:")));
    assert!(records
        .iter()
        .any(|r| r.action.starts_with("resource_denied:")));
    assert!(records
        .iter()
        .any(|r| r.action.starts_with("unmanaged_agent:")));
    assert!(records[0].to_json().contains("\"actor\""));

    // 9. METRICS — the Prometheus registry reflects what happened.
    let metrics = gw.metrics();
    assert_eq!(
        metrics.counter("gm_agent_actions_total", &[("outcome", "executed")]),
        2, // the auto call + the approved review
    );
    assert_eq!(
        metrics.counter("gm_agent_actions_total", &[("outcome", "review")]),
        1,
    );
    assert_eq!(
        metrics.counter("gm_agent_actions_total", &[("outcome", "denied_scope")]),
        1,
    );
    assert_eq!(
        metrics.counter("gm_agent_actions_total", &[("outcome", "unmanaged")]),
        1,
    );
    assert_eq!(
        metrics.counter("gm_agent_resource_reads_total", &[("result", "ok")]),
        1,
    );
    assert_eq!(
        metrics.counter("gm_agent_resource_reads_total", &[("result", "denied")]),
        1,
    );
    assert!(metrics
        .render_prometheus()
        .contains("# TYPE gm_agent_actions_total counter"));
}
