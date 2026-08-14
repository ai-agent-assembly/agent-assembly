# Fixture companion for rule R16, AAASM-5678

The Markdown half of the R16 comparison reads one column out of the tables whose
first header cell is `ID`, and only the terms a cell puts in **bold**. This file
is the smallest input that exercises that: one table, one row, one bold term.

It states the same value as `seed-r16.yaml`, so a fixture's divergence from the
seed is a divergence from the companion too — which is how the real manifest
sits, with the seed and its companion agreeing and the manifest the outlier by
design.

| ID | Capability / action | Coverage | Bnd |
|---|---|---|---|
| **T1** | A worked example row carrying one of every required field | **Denied before execution** | B3 |
