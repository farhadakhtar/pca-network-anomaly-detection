# Raw dataset location

Place public flow-based network intrusion datasets here (or configure another path in an experiment config). Raw datasets are intentionally not committed because they are large, may have separate licenses, and should be obtained from their official sources.

Expected format:

- CSV file(s), one network flow per row.
- A label column such as `Label`, `label`, `Attack`, `attack_cat`, or configured explicitly.
- Benign rows should use a configured benign label, commonly `BENIGN`, `Benign`, `Normal`, or `normal`.
- Feature columns should be numeric flow-level quantities. Non-numeric identifiers/timestamps are preserved for metadata only unless configured otherwise.

Examples of compatible datasets include CICIDS-family datasets, UNSW-NB15, or similar flow-feature intrusion datasets.

Experiments locate data through `configs/*.yaml` using `dataset.path`. If no real dataset is available, use `dataset.synthetic: true`; synthetic results are only smoke-test/CI evidence and must not be reported as real cybersecurity findings.
