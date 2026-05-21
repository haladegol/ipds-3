# HADES System Requirements Specification (IEEE 830 Standard)

## 4.4 Functional Requirements
The following requirements define the fundamental actions that the HADES IDPS must perform to satisfy the user's forensic and security objectives.

### FR-01: Full-Fidelity Data Ingestion
- **Description**: The system shall ingest and process network telemetry files (CSV/PCAP) containing up to 46 million records without sampling or data loss.
- **Priority**: High
- **Requirement**: The ingestion engine must utilize chunked processing to maintain system stability while reading multi-gigabyte datasets.

### FR-02: Forensic Asset Discovery
- **Description**: The system shall automatically identify and categorize all unique network entities.
- **Requirement**: The system must perform a 100% census of unique Source and Destination IP addresses, mapping them to "Network Clients" and "Network Hosts" respectively.

### FR-03: Behavioral Device Classification
- **Description**: The system shall classify discovered assets based on interaction patterns.
- **Requirement**: Using connection density and IP patterns (.1, .254), the system must categorize assets into Gateways, Servers, and Workstations.

### FR-04: L4-L7 Service Inference
- **Description**: The system shall infer active services by auditing port usage.
- **Requirement**: The system must cross-reference discovered ports against the HADES Service Matrix to identify roles such as "HTTP Web Server," "SSH Remote Access," or "MySQL Database."

### FR-05: Signature-Based Threat Detection
- **Description**: The system shall identify malicious patterns using a synchronized signature database.
- **Requirement**: The system must match network flows against 10,000+ real-world threat signatures (ET Open) and categorize attacks (e.g., DoS, Brute-Force, XSS).

### FR-06: Dynamic Topology Visualization
- **Description**: The system shall generate a logical map of the network architecture.
- **Requirement**: The system must detect the central hub (Gateway) and render either a "Star Topology" or "Mesh Network" diagram based on inferred behavioral relationships.

---

## 4.5 Non-Functional Requirements
The following requirements define the quality attributes, constraints, and operational standards of the HADES platform.

### NFR-01: Data Integrity (Accuracy)
- **Standard**: 100% Forensic Fidelity
- **Requirement**: The system must guarantee that all KPI counts (Clients, Hosts, Flows) exactly match the raw input data. Numeric artifacts (e.g., scientific notation) must be surgically excluded from identity columns.

### NFR-02: Performance & Latency
- **Standard**: Real-time Responsiveness
- **Requirement**: Post-initial scan, the system must utilize a persistent `comprehensive_cache` to render analytical dashboards in under 2 seconds, regardless of the underlying dataset size (46M+ records).

### NFR-03: Scalability
- **Standard**: Vertical Scalability
- **Requirement**: The processing engine must support datasets exceeding 10GB in size by utilizing memory-efficient iterator patterns (`chunksize`) to prevent OOM (Out of Memory) failures.

### NFR-04: Usability & Accessibility
- **Standard**: High-Contrast Forensic UI
- **Requirement**: The interface must adhere to the HADES Dark Green design system, utilizing high-contrast white/green text (e.g., `#fff` on `#0c1a18`) to ensure 100% readability of technical matrices.

### NFR-05: Security & Privacy
- **Standard**: Role-Based Access Control (RBAC)
- **Requirement**: Access to the forensic database and analysis results must be restricted to authenticated users. All session-specific data must be isolated per user ID.

### NFR-06: Portability
- **Standard**: Cross-Platform Compatibility
- **Requirement**: The application must be deployable as a Flask-based web service compatible with Windows, Linux, and MacOS environments using standard Python dependencies.
