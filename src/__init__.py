"""PCA-based network anomaly detection package (one-class, benign-train only)."""

__version__ = "0.1.0"

SEED = 42

BENIGN_LABEL = "BENIGN"

# Canonical attack taxonomy (ERD E2 / DRD D-04). Order is fixed for reporting.
ATTACK_CATEGORIES = ["DDoS", "PortScan", "Botnet", "BruteForce", "Other"]

LABEL_COL = "Label"
CATEGORY_COL = "AttackCategory"
FLOW_ID_COL = "flow_id"
