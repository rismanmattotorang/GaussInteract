// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! A minimal, Prometheus-compatible in-process metrics registry (spec §VIII.A).
//!
//! Counters and gauges are keyed by name plus an optional set of labels and
//! render in the Prometheus text exposition format, so a scrape endpoint (added
//! behind a feature later) can serve them directly. Dependency-free by design.

use std::collections::BTreeMap;

/// A metric time-series: a name plus a sorted label set.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Series {
    name: String,
    labels: Vec<(String, String)>,
}

impl Series {
    fn new(name: &str, labels: &[(&str, &str)]) -> Self {
        let mut labels: Vec<(String, String)> = labels
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        labels.sort();
        Self {
            name: name.to_owned(),
            labels,
        }
    }

    fn render(&self) -> String {
        if self.labels.is_empty() {
            return self.name.clone();
        }
        let inner = self
            .labels
            .iter()
            .map(|(k, v)| format!("{k}=\"{}\"", escape(v)))
            .collect::<Vec<_>>()
            .join(",");
        format!("{}{{{inner}}}", self.name)
    }
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// An in-process registry of counters and gauges.
#[derive(Debug, Default)]
pub struct Metrics {
    counters: BTreeMap<Series, u64>,
    gauges: BTreeMap<Series, i64>,
}

impl Metrics {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment a counter by one.
    pub fn inc_counter(&mut self, name: &str, labels: &[(&str, &str)]) {
        self.add_counter(name, labels, 1);
    }

    /// Add `n` to a counter.
    pub fn add_counter(&mut self, name: &str, labels: &[(&str, &str)], n: u64) {
        *self.counters.entry(Series::new(name, labels)).or_insert(0) += n;
    }

    /// Set a gauge to `value`.
    pub fn set_gauge(&mut self, name: &str, labels: &[(&str, &str)], value: i64) {
        self.gauges.insert(Series::new(name, labels), value);
    }

    /// Read the current value of a counter (0 if unseen).
    pub fn counter(&self, name: &str, labels: &[(&str, &str)]) -> u64 {
        self.counters
            .get(&Series::new(name, labels))
            .copied()
            .unwrap_or(0)
    }

    /// Render all metrics in the Prometheus text exposition format.
    pub fn render_prometheus(&self) -> String {
        let mut out = String::new();
        render_group(&mut out, &self.counters, "counter");
        render_group(&mut out, &self.gauges, "gauge");
        out
    }
}

fn render_group<V: std::fmt::Display>(out: &mut String, series: &BTreeMap<Series, V>, kind: &str) {
    // BTreeMap iteration is ordered by (name, labels), so series of the same
    // metric are already adjacent — emit one `# TYPE` header per name.
    let mut current: Option<&str> = None;
    for (s, v) in series {
        if current != Some(s.name.as_str()) {
            out.push_str(&format!("# TYPE {} {kind}\n", s.name));
            current = Some(s.name.as_str());
        }
        out.push_str(&s.render());
        out.push(' ');
        out.push_str(&v.to_string());
        out.push('\n');
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_accumulate_per_label_set() {
        let mut m = Metrics::new();
        m.inc_counter("gm_agent_actions_total", &[("outcome", "executed")]);
        m.inc_counter("gm_agent_actions_total", &[("outcome", "executed")]);
        m.inc_counter("gm_agent_actions_total", &[("outcome", "denied")]);
        assert_eq!(
            m.counter("gm_agent_actions_total", &[("outcome", "executed")]),
            2
        );
        assert_eq!(
            m.counter("gm_agent_actions_total", &[("outcome", "denied")]),
            1
        );
    }

    #[test]
    fn renders_prometheus_text() {
        let mut m = Metrics::new();
        m.add_counter("gm_agent_actions_total", &[("outcome", "executed")], 3);
        m.set_gauge("gm_agent_pending_approvals", &[], 2);
        let text = m.render_prometheus();
        assert!(text.contains("# TYPE gm_agent_actions_total counter"));
        assert!(text.contains("gm_agent_actions_total{outcome=\"executed\"} 3"));
        assert!(text.contains("# TYPE gm_agent_pending_approvals gauge"));
        assert!(text.contains("gm_agent_pending_approvals 2"));
    }
}
