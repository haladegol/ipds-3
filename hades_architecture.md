# HADES Core Architecture Diagram

This diagram maps out the exact flow of data through the HADES core, displaying how the **IDS Engine (The Brain)** and the **IPS Engine (The Muscle)** work seamlessly together to intercept threats.

> [!TIP]
> **Reading Guide**: Follow the arrows starting from the **Ingestion Phase**. The blue blocks represent the machine-learning pipeline, while the red blocks represent active defensive enforcement.

```mermaid
flowchart TD
    %% Styling Definitions
    classDef default fill:#2d3436,stroke:#8fb8a8,color:#fff,stroke-width:1px
    classDef ids fill:#1b4f72,stroke:#408A71,color:#fff,stroke-width:2px
    classDef ips fill:#7b241c,stroke:#ff6b6b,color:#fff,stroke-width:2px
    classDef data fill:#145a32,stroke:#B0E4CC,color:#fff,stroke-width:2px
    classDef db fill:#4a235a,stroke:#a29bfe,color:#fff,stroke-width:2px

    %% Ingestion Pipeline
    subgraph INGRESS ["1. Ingestion Phase"]
        direction TB
        UPLOAD["Network Data Upload (CSV)"]:::data
        NORM["Normalisation & Hex/URL Decoding"]:::data
        UPLOAD --> NORM
    end

    %% IDS Engine (ML Pipeline)
    subgraph IDS ["2. HADES IDS (The Brain)"]
        direction TB
        S1["Stage 1: Binary Classifier (Normal vs Anomaly)"]:::ids
        S2["Stage 2: Attack Categorisers (DoS, Web, Botnet, etc)"]:::ids
        S3["Stage 3: Specific Attack Recognition"]:::ids
        
        NORM -->|"Analyses Flow"| S1
        S1 -->|"Anomaly Caught"| S2
        S2 -->|"Attack Class Known"| S3
        S1 -->|"Normal Flow"| PASS["Passthrough (Whitelisted)"]:::data
    end

    %% IPS Engine (Enforcement)
    subgraph IPS ["3. HADES IPS (The Muscle)"]
        direction TB
        REP["Task 1: Reputation Engine (Kill known IPs)"]:::ips
        SIG["Task 2: Dynamic Signature Matching (Scan Raw Data)"]:::ips
        ACT["Task 3: Automated Enforcement (Drop packets)"]:::ips
        TAC["Task 4: Tactical Response (Quarantine, Scrub, Decoy)"]:::ips

        NORM -->|"Pre-Check Flow Details"| REP
        S3 -->|"Pass Context to IPS"| SIG
        REP -->|"Traffic Allowed"| SIG
        SIG -->|"Regex Signature Pattern Match"| ACT
        ACT -->|"Active Threat Escalation"| TAC
    end

    %% Persistence and Intelligence Layers
    subgraph DATA ["4. Persistence & Logging"]
        direction LR
        AL["Attack Logs (Hybrid Dashboards)"]:::db
        BL["Blocked IP Registry (Firewall Engine)"]:::db
        SL["System Logs (Admin Auditing)"]:::db

        S3 -.->|"Log Incident"| AL
        ACT -.->|"Write Firewall Rule"| BL
        TAC -.->|"Log System Modification"| SL
    end
```

### Components Breakdown

1.  **Ingestion Phase**: This is the entry point where you upload your standard CIC-IDS2018 datasets. It strips away incompatible inputs, resolves `NaN` and `infinite` fields, and URL/Hex decodes the payload parameters so malware cannot hide.
2.  **HADES IDS**: This section uses your pre-trained models. First, it identifies if a flow is purely an anomaly. If it is, the flow gets thrown to the secondary neural nets (Stage 2 & 3) to correctly identify whether it's a brute force, an SQL injection, or lateral movement.
3.  **HADES IPS**: This is what you just enabled! It doesn't rely solely on machine-learning guesswork. It checks the dataset rows directly against a hardcoded whitelist/blacklist (Reputation Engine) and hundreds of custom regex rules (Signature Matching). When something is identified, it drops the flow and triggers active measures like quarantining.
4.  **Persistence**: The resulting actions from both tools are split. The IDS writes to `AttackLog` to render your Hybrid Dashboards, while the IPS writes to `SystemLog` and `BlockedIP` to actively command the firewall rules on the Response Dashboard.
