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

  /// The read-only audit log for the supervisor view (oldest first), in the
  /// same [GaussAuditRecord] shape the GaussMatrix server emits.
  List<GaussAuditRecord> get auditLog;

  /// Whether the audit chain verifies intact (no retroactive tampering).
  bool verifyAudit();
}

/// Pure-Dart implementation of [GaussCore], faithful to the Rust scaffold so
/// the agentic UI flows behave identically once the FFI replaces it.
class GaussCoreStub implements GaussCore {
  int _nextId = 0;
  final List<GaussApprovalRequest> _pending = <GaussApprovalRequest>[];
  final List<GaussAuditRecord> _audit = <GaussAuditRecord>[];

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
  List<GaussAuditRecord> get auditLog =>
      List<GaussAuditRecord>.unmodifiable(_audit);

  @override
  bool verifyAudit() {
    var expectedPrev = 0;
    for (final record in _audit) {
      if (record.prevHash != expectedPrev) return false;
      if (record.hash != _digest(record.actor, record.action, record.prevHash)) {
        return false;
      }
      expectedPrev = record.hash;
    }
    return true;
  }

  void _appendAudit(String actor, String action) {
    final prevHash = _audit.isEmpty ? 0 : _audit.last.hash;
    _audit.add(
      GaussAuditRecord(
        seq: _audit.length,
        actor: actor,
        action: action,
        prevHash: prevHash,
        hash: _digest(actor, action, prevHash),
      ),
    );
  }

  // Placeholder digest mirroring the Rust scaffold; the FFI core uses a
  // cryptographic hash (SHA-256 / BLAKE3). See gauss-core/src/agent.rs.
  static int _digest(String actor, String action, int prevHash) =>
      Object.hash(actor, action, prevHash);
}

/// The wire string for a classification, matching the GaussMatrix gateway
/// (`gm-agent`'s `ActionClass`).
extension GaussActionClassWire on GaussActionClass {
  /// `"auto"` / `"review"` / `"forbidden"`.
  String get wire => switch (this) {
    GaussActionClass.auto => 'auto',
    GaussActionClass.review => 'review',
    GaussActionClass.forbidden => 'forbidden',
  };
}

/// Parse a classification from its wire string, or null if unknown.
GaussActionClass? gaussActionClassFromWire(String value) => switch (value) {
  'auto' => GaussActionClass.auto,
  'review' => GaussActionClass.review,
  'forbidden' => GaussActionClass.forbidden,
  _ => null,
};

/// An agent's capability grant, parsed from the `m.gauss.agent.capability`
/// room-state content the GaussMatrix gateway publishes (§IV.C).
///
/// This mirrors the server's `CapabilityGrant`: the client decodes the same
/// content, so it can show a supervisor what an agent is allowed to do and
/// preview how a tool call would be classified — without trusting anything it
/// cannot validate.
class GaussCapabilityGrant {
  const GaussCapabilityGrant({
    required this.agent,
    required this.allowedTools,
    required this.accessibleRooms,
    required this.rateLimitPerMin,
    required this.dailyCallLimit,
    required this.dailyTokenBudget,
    required this.defaultClass,
    required this.overrides,
  });

  /// The agent this grant scopes.
  final String agent;

  /// Tools the agent may call at all.
  final List<String> allowedTools;

  /// Rooms the agent may access.
  final List<String> accessibleRooms;

  /// Maximum tool calls per minute (0 = unlimited).
  final int rateLimitPerMin;

  /// Maximum tool calls per day (0 = unlimited).
  final int dailyCallLimit;

  /// Maximum tokens the agent may consume per day (0 = unlimited) — agentic
  /// FinOps the supervisor can see and govern.
  final int dailyTokenBudget;

  /// Classification for tools without an explicit override.
  final GaussActionClass defaultClass;

  /// Per-tool classification overrides.
  final Map<String, GaussActionClass> overrides;

  /// Decode from `m.gauss.agent.capability` event content. Returns null if the
  /// content is malformed — the same fields the server re-validates (§IV.C).
  static GaussCapabilityGrant? fromContent(Map<String, Object?> content) {
    final agent = content['agent'];
    final rate = content['rate_limit_per_min'];
    final defaultClassValue = content['default_class'];
    if (agent is! String || rate is! int || defaultClassValue is! String) {
      return null;
    }
    // Optional for backward compatibility, mirroring the server decode: older
    // content (or a partial mirror) may omit these, meaning "unlimited".
    final dailyCallValue = content['daily_call_limit'];
    final dailyTokenValue = content['daily_token_budget'];
    if (dailyCallValue is! int && dailyCallValue != null) return null;
    if (dailyTokenValue is! int && dailyTokenValue != null) return null;
    final dailyCallLimit = dailyCallValue is int ? dailyCallValue : 0;
    final dailyTokenBudget = dailyTokenValue is int ? dailyTokenValue : 0;
    final defaultClass = gaussActionClassFromWire(defaultClassValue);
    final allowedTools = _stringList(content['allowed_tools']);
    final accessibleRooms = _stringList(content['accessible_rooms']);
    final overridesValue = content['overrides'];
    if (defaultClass == null ||
        allowedTools == null ||
        accessibleRooms == null ||
        overridesValue is! List) {
      return null;
    }
    final overrides = <String, GaussActionClass>{};
    for (final Object? entry in overridesValue) {
      if (entry is! List || entry.length != 2) return null;
      final Object? tool = entry[0];
      final Object? classValue = entry[1];
      if (tool is! String || classValue is! String) return null;
      final cls = gaussActionClassFromWire(classValue);
      if (cls == null) return null;
      overrides[tool] = cls;
    }
    return GaussCapabilityGrant(
      agent: agent,
      allowedTools: allowedTools,
      accessibleRooms: accessibleRooms,
      rateLimitPerMin: rate,
      dailyCallLimit: dailyCallLimit,
      dailyTokenBudget: dailyTokenBudget,
      defaultClass: defaultClass,
      overrides: overrides,
    );
  }

  /// Classify a tool invocation in a room, mirroring the gateway. A tool or
  /// room outside the grant resolves to [GaussActionClass.forbidden].
  GaussActionClass classify(String tool, String room) {
    if (!accessibleRooms.contains(room) || !allowedTools.contains(tool)) {
      return GaussActionClass.forbidden;
    }
    return overrides[tool] ?? defaultClass;
  }
}

/// One structured audit record as emitted by GaussMatrix `gm-obs`
/// (`AuditRecord`), for the supervisor audit view.
class GaussAuditRecord {
  const GaussAuditRecord({
    required this.seq,
    required this.actor,
    required this.action,
    required this.prevHash,
    required this.hash,
  });

  /// Position in the chain (0-based, oldest first).
  final int seq;

  /// The principal the entry concerns.
  final String actor;

  /// The recorded gateway decision/event.
  final String action;

  /// Hash committing to the previous entry.
  final int prevHash;

  /// Hash of this entry.
  final int hash;

  /// Decode from the JSON object the SIEM stream emits, or null if malformed.
  static GaussAuditRecord? fromJson(Map<String, Object?> json) {
    final seq = json['seq'];
    final actor = json['actor'];
    final action = json['action'];
    final prevHash = json['prev_hash'];
    final hash = json['hash'];
    if (seq is! int ||
        actor is! String ||
        action is! String ||
        prevHash is! int ||
        hash is! int) {
      return null;
    }
    return GaussAuditRecord(
      seq: seq,
      actor: actor,
      action: action,
      prevHash: prevHash,
      hash: hash,
    );
  }
}

List<String>? _stringList(Object? value) {
  if (value is! List) return null;
  final result = <String>[];
  for (final Object? element in value) {
    if (element is! String) return null;
    result.add(element);
  }
  return result;
}
