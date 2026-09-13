# Open Items / TODO

## Phase 5 — Scenario data (blocked on teammate)
- [ ] Waiting on teammate: run `df['Attack Type'].unique()` on CICIDS cleaned dataset
- [ ] If `PortScan` exists as its own category: rebuild `port_scan.jsonl` from real CICIDS rows
- [ ] If `PortScan` was merged into a broader category: keep `port_scan.jsonl` synthetic (current version), document why in README
- [ ] Same decision applies to `benign.jsonl` — currently synthetic placeholder either way