01 — Contexte & Objectifs
01 — Structurer les données
Transformer les données RAW de vulnérabilités en objets métier standardisés et exploitables.
02 — Fiabiliser la donnée
Contrôler, normaliser et tracer les anomalies avant toute exploitation par le système IA.
03 — Enrichir les Findings
Associer les vulnérabilités à leur contexte applicatif afin d’obtenir une donnée plus complète.
04 — Préparer la persistance
Construire une base PostgreSQL structurée pour centraliser et rendre les données accessibles aux futurs agents IA.
En bas de la slide, tu peux mettre simplement :
Objectif : construire une fondation Data fiable pour le système multi-agents IA de gestion des vulnérabilités.
02 — Data Pipeline & Enrichment
From Raw Findings to Enriched Business Objects
Pipeline
RAW FINDING
     ↓
PARSER V1
Clean • Normalize • Validate • Map
     ↓
obj_finding
     │
     │  +  obj_application
     ↓
APPLICATION ENRICHMENT
Matching by AUID
     ↓
obj_findings_enriched
Parser V1
35 061 findings generated
- RAW → obj_finding mapping
- Data cleaning & normalization
- Business rules & calculated fields
- Validation & anomaly detection
- KRI controls
- Retry mechanism & reporting
42 ERROR anomalies identified and diagnosed
Findings are preserved despite detected data-quality issues.
Application Enrichment
Mets les 4 KPI en gros :
35 022	100%	0	39
Findings with AUID	Match Rate	Unmatched	Missing AUID


Puis juste en dessous :
Matching Key: AUID
Enriched Fields:
Application Name • Trigram • AppSec Profile
Data Quality Decision
Business Lines ≠ IT Sub Cluster
Different business semantics identified between the two sources. Both values are kept separately to prevent incorrect data overwriting.

Et termine la slide avec une bande horizontale bien visible :
35 022 ENRICHED FINDINGS · 100% MATCH RATE · 0 CONFLICT · 0 FINDING LOST

03 — PostgreSQL & Results
From Enriched Objects to a Relational Data Model
PostgreSQL Architecture
Au centre de la slide :
                    APPLICATION
                         │
                         ▼
SERVER ─────────────► FINDING ◄──────────── VULNERABILITY
                         │
                         ▼
                   PIPELINE RUN
                         │
                         ▼
                     AGENT RUN
                      /      \
                     ▼        ▼
                 ANOMALY   ARTIFACT
Relational Data Model
Core Business Entities
Application • Server • Vulnerability • Finding
Execution & Traceability
Pipeline Run • Agent • Agent Run • Anomaly • Artifact
Puis une ligne courte :
PK/FK • Constraints • Indexes • Transactions • Rollback • Source Payload Traceability

PostgreSQL Dry-Run
Mets les 4 KPI en très gros :
35 061	10	261	555
Findings Mapped	Applications	Servers	Vulnerabilities


Puis juste en dessous, trois indicateurs :
0
Mapping Errors
✓
Input = Output
READY
Dry-Run Status
Et la phrase importante :
Full PostgreSQL persistence flow validated offline on the complete dataset before real database deployment.

Ce que tu as réellement préparé
Tu peux mettre quatre petits blocs :
MAPPING
Enriched objects → relational entities
REPOSITORY
Parameterized PostgreSQL operations
LOADER
End-to-end data loading workflow
TRANSACTION SAFETY
Commit • Rollback • No partial silent load


01 — Contexte & Objectifs
Tes 4 objectifs :
Structurer → Fiabiliser → Enrichir → Persister
02 — Data Pipeline & Enrichment
Tu montres :
RAW → Parser → obj_finding + obj_application → Enrichment
Avec tes résultats :
35 061 findings • 35 022 enrichis • 100 % match • 0 conflit
03 — PostgreSQL & Results


┌──────────────────────────────────────────────────────────────┐
│ 03 — POSTGRESQL & RESULTS                                   │
│ From Enriched Objects to a Relational Data Model            │
├────────────────────────────┬─────────────────────────────────┤
│                            │                                 │
│   RELATIONAL MODEL         │     POSTGRESQL DRY-RUN         │
│                            │                                 │
│       APPLICATION          │  35 061   10    261    555     │
│            │               │  Findings  Apps  Servers CVEs  │
│            ▼               │                                 │
│ SERVER → FINDING ← VULN.   │       0 MAPPING ERRORS          │
│            │               │       INPUT = OUTPUT ✓          │
│       PIPELINE RUN         │                                 │
│            ↓               │       STATUS: READY             │
│        AGENT RUN           │                                 │
│       ↙         ↘          │                                 │
│  ANOMALY      ARTIFACT     │                                 │
│                            │                                 │
├────────────────────────────┴─────────────────────────────────┤
│ MAPPING  │ REPOSITORY │ LOADER │ TRANSACTION & ROLLBACK     │
├──────────────────────────────────────────────────────────────┤
│ ✓ Persistence flow validated on the complete dataset        │
└──────────────────────────────────────────────────────────────┘