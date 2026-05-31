// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
//
// SPDX-License-Identifier: AGPL-3.0-or-later

/// Dart-side facade for the shared Rust core (`gauss-core`).
///
/// GaussInteract's target architecture (GaussInteract-SPECS §V) is a single
/// Flutter UI over one memory-safe Rust core, reached through
/// `uniffi`-generated bindings and a thin FFI shim. Those bindings do not exist
/// yet (Phase 2 of the roadmap), so this file defines the **integration seam**:
/// the API the UI will call, with a pure-Dart [GaussCoreStub] implementation so
/// the agentic approval/audit flows can be built and tested in the app today.
///
/// When the FFI lands, `GaussCore.stub()` is replaced by `GaussCore.ffi()`
/// wrapping the generated bindings — the rest of the app keeps calling this
/// same interface.
library;

/// Namespaced agentic event types, mirroring `gauss_core::events` (§IV.B).
abstract class GaussAgentEvents {
  /// An agent's MCP tool invocation.
  static const String toolCall = 'm.gauss.agent.tool_call';

  /// The result the gateway reflected back into the room.
  static const String toolResult = 'm.gauss.agent.tool_result';

  /// An agent's capability grant, carried as room state.
  static const String capability = 'm.gauss.agent.capability';

  /// A human approve/deny receipt.
  static const String approval = 'm.gauss.agent.approval';
}

/// How an agent action is classified (§IV.C).
enum GaussActionClass { auto, review, forbidden }

/// A human's decision on a pending approval.
enum GaussApprovalDecision { approve, deny }

/// A pending human-in-the-loop approval prompt (§IV.C, §V.F).
class GaussApprovalRequest {
  const GaussApprovalRequest({
    required this.id,
    required this.agent,
    required this.tool,
    required this.proposedAction,
  });

  /// Identifier linking the prompt to its rendered timeline item.
  final int id;

  /// The agent (a Matrix identity) requesting the action.
  final String agent;

  /// The tool the agent wishes to invoke.
  final String tool;

  /// The proposed action, shown to the human in full.
  final String proposedAction;
}

/// One entry of the tamper-evident, hash-chained audit log (§IV.D).
class GaussAuditEntry {
  const GaussAuditEntry({
    required this.agent,
    required this.event,
    required this.prevHash,
    required this.hash,
  });

  /// The agent the entry concerns.
  final String agent;

  /// A description of the recorded gateway decision/event.
  final String event;

  /// Hash committing to the previous entry (0 for the genesis entry).
  final int prevHash;

  /// Hash of this entry, over its content and [prevHash].
  final int hash;
}

/// The single object the UI talks to, mirroring `gauss_core::GaussCore`.
abstract class GaussCore {
  /// The in-app stub implementation used until the FFI bindings land.
  factory GaussCore.stub() = GaussCoreStub;

  /// The core's version string.
  String get version;

  /// Whether a session is currently active.
  bool get isAuthenticated;

  /// Register a `review`-class action awaiting human approval; returns its id.
  int requestApproval({
    required String agent,
    required String tool,
    required String proposedAction,
  });

  /// Approval prompts the UI should render.
  List<GaussApprovalRequest> get pendingApprovals;

  /// Resolve a pending approval; returns whether the id was found.
  bool resolveApproval(int id, GaussApprovalDecision decision);

  /// The read-only audit log for the supervisor view (oldest first).
  List<GaussAuditEntry> get auditLog;

  /// Whether the audit chain verifies intact (no retroactive tampering).
  bool verifyAudit();
}

/// Pure-Dart implementation of [GaussCore], faithful to the Rust scaffold so
/// the agentic UI flows behave identically once the FFI replaces it.
class GaussCoreStub implements GaussCore {
  int _nextId = 0;
  final List<GaussApprovalRequest> _pending = <GaussApprovalRequest>[];
  final List<GaussAuditEntry> _audit = <GaussAuditEntry>[];

  @override
  String get version => '0.0.1-stub';

  @override
  bool get isAuthenticated => false;

  @override
  int requestApproval({
    required String agent,
    required String tool,
    required String proposedAction,
  }) {
    final id = _nextId++;
    _appendAudit(agent, 'approval_requested: $tool');
    _pending.add(
      GaussApprovalRequest(
        id: id,
        agent: agent,
        tool: tool,
        proposedAction: proposedAction,
      ),
    );
    return id;
  }

  @override
  List<GaussApprovalRequest> get pendingApprovals =>
      List<GaussApprovalRequest>.unmodifiable(_pending);

  @override
  bool resolveApproval(int id, GaussApprovalDecision decision) {
    final index = _pending.indexWhere((request) => request.id == id);
    if (index < 0) return false;
    final request = _pending.removeAt(index);
    final verb =
        decision == GaussApprovalDecision.approve ? 'approved' : 'denied';
    _appendAudit(request.agent, '$verb: ${request.tool}');
    return true;
  }

  @override
  List<GaussAuditEntry> get auditLog =>
      List<GaussAuditEntry>.unmodifiable(_audit);

  @override
  bool verifyAudit() {
    var expectedPrev = 0;
    for (final entry in _audit) {
      if (entry.prevHash != expectedPrev) return false;
      if (entry.hash != _digest(entry.agent, entry.event, entry.prevHash)) {
        return false;
      }
      expectedPrev = entry.hash;
    }
    return true;
  }

  void _appendAudit(String agent, String event) {
    final prevHash = _audit.isEmpty ? 0 : _audit.last.hash;
    _audit.add(
      GaussAuditEntry(
        agent: agent,
        event: event,
        prevHash: prevHash,
        hash: _digest(agent, event, prevHash),
      ),
    );
  }

  // Placeholder digest mirroring the Rust scaffold; the FFI core uses a
  // cryptographic hash (SHA-256 / BLAKE3). See gauss-core/src/agent.rs.
  static int _digest(String agent, String event, int prevHash) =>
      Object.hash(agent, event, prevHash);
}
