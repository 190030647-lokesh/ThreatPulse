# ThreatPulse

![Salesforce](https://img.shields.io/badge/Salesforce-API%20v65-00A1E0?style=flat&logo=salesforce&logoColor=white)
![Apex Tests](https://img.shields.io/badge/Apex%20Tests-41%20Passing-brightgreen?style=flat)
![LWC](https://img.shields.io/badge/LWC-4%20Components-blue?style=flat)
![Flows](https://img.shields.io/badge/Flows-6%20Automated-orange?style=flat)
![License](https://img.shields.io/badge/License-MIT-lightgrey?style=flat)

A **cybersecurity threat intelligence platform** built on Salesforce Lightning. ThreatPulse enables security teams to track threats, manage incidents, monitor indicators of compromise (IOCs), and sync threat intelligence from external feeds — all within a single Salesforce native app.

🔗 **Live Demo:** [resilient-bear-nh22h-dev-ed.trailblaze.my.salesforce.com/lightning/app/ThreatPulse](https://resilient-bear-nh22h-dev-ed.trailblaze.my.salesforce.com/lightning/app/ThreatPulse)

> Demo credentials available on request.

---

## Screenshots

| Dashboard | Threat List | Incident Tracker |
|-----------|-------------|-----------------|
| ![Dashboard](assets/screenshots/dashboard.png) | ![Threats](assets/screenshots/threats.png) | ![Incidents](assets/screenshots/incidents.png) |

| IOC Viewer | Threat Detail |
|------------|--------------|
| ![IOCs](assets/screenshots/iocs.png) | ![Detail](assets/screenshots/threat-detail.png) |

---

## Features

| Feature | Description |
|---------|-------------|
| **Threat Management** | Create, track, and close threats with P1–P4 severity and full lifecycle status (New → In Progress → Contained → Closed) |
| **Incident Tracker** | Auto-creates incidents for Critical/High threats; assign analysts, add resolution notes |
| **IOC Viewer** | Search and filter Indicators of Compromise by type (IP, Domain, Hash, URL, Email); one-click deactivation |
| **Live Dashboard** | KPI cards for open threats, incidents, IOCs; severity/category charts; recent activity feed |
| **Threat Feed Sync** | Batch-based ingestion from external feeds (Custom JSON + AlienVault OTX format) |
| **Automated Flows** | 6 flows: email alerts, auto-incident creation, auto-deactivation of IOCs on threat close |
| **Role-Based Access** | Admin, Analyst, and ReadOnly permission sets with field-level security |

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Lightning App                       │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────┐  │
│  │ threatList  │  │threatDashboard│  │incidentTracker│ │
│  │    (LWC)   │  │    (LWC)     │  │   (LWC)    │  │
│  └──────┬──────┘  └──────┬───────┘  └─────┬──────┘  │
│         └────────────────┼────────────────┘          │
│                   Apex Controllers                    │
│     ThreatController  │  IncidentController           │
│     IOCController     │  DashboardMetricsController   │
│                   Apex Service Layer                  │
│     ThreatService  │  IncidentService  │  IOCService  │
│                   Custom Objects                      │
│  Threat__c │ Incident__c │ IOC__c │ Threat_Feed__c   │
│  MITRE_Technique__c │ Threat_Actor__c │ TF_Config     │
└─────────────────────────────────────────────────────┘
```

---

## Tech Stack

| Layer | Technology | Detail |
|-------|-----------|--------|
| Frontend | Lightning Web Components | 4 components: threatList, threatDashboard, incidentTracker, iocViewer |
| Backend | Apex | Service layer pattern, Controllers, Batch jobs |
| Automation | Salesforce Flows | 6 flows for email alerts, incident creation, IOC deactivation |
| Data Model | Custom Objects | 7 objects with relationships, validation rules, formula fields |
| Security | Permission Sets | 3 sets (Admin/Analyst/ReadOnly) + `WITH SECURITY_ENFORCED` on all SOQL |
| Testing | Apex Test Classes | 41 tests across 5 test classes — 100% pass rate |
| Config | Custom Metadata | Configurable thresholds, email recipients, auto-close days |

---

## Data Model

| Object | Purpose | Key Fields |
|--------|---------|-----------|
| `Threat__c` | Core threat record | Severity (P1–P4), Status, Category, Confidence Score |
| `Incident__c` | Security incidents | Priority, Assigned Analyst, Resolution Date |
| `Indicator_of_Compromise__c` | IOC tracking | Type, Value, Confidence, Active flag |
| `Threat_Feed__c` | External feed config | Feed URL, Type (JSON/OTX), Sync Frequency |
| `Threat_Actor__c` | Known threat actors | Origin, Sophistication, Motivation |
| `MITRE_Technique__c` | ATT&CK framework | Technique ID, Tactic, Mitigation |

---

## Automated Flows

| Flow | Trigger | Action |
|------|---------|--------|
| `Threat_AutoCreate_Incident` | Threat created with P1/P2 severity | Auto-creates linked Incident record |
| `Threat_Critical_High_Email_Alert` | P1/P2 Threat created | Sends email alert to configured recipients |
| `Threat_Deactivate_On_Close` | Threat status → Closed | Sets `Is_Active__c = false` |
| `Threat_Deactivate_Related_IOCs` | Threat closed | Deactivates all linked IOC records |
| `Incident_Critical_High_Email_Alert` | Incident created | Sends analyst notification email |
| `Incident_AutoStamp_Resolved_Date` | Incident status → Resolved | Stamps `Resolution_Date__c` automatically |

---

## Severity Levels

| Level | Label | Auto-creates Incident | Email Alert |
|-------|-------|-----------------------|-------------|
| P1 | Critical | ✅ Yes | ✅ Yes |
| P2 | High | ✅ Yes | ✅ Yes |
| P3 | Medium | ❌ No | ❌ No |
| P4 | Low | ❌ No | ❌ No |

---

## Quick Start

**Prerequisites:** [Salesforce CLI](https://developer.salesforce.com/tools/salesforcecli) installed

```bash
# 1. Authenticate your org
sf org login web --alias MyOrg

# 2. Deploy all metadata
sf project deploy start --source-dir force-app --target-org MyOrg

# 3. Assign permissions
sf org assign permset --name ThreatPulse_Admin --target-org MyOrg

# 4. Load sample data
sf apex run --file scripts/apex/seed_data.apex --target-org MyOrg

# 5. Open the app
sf org open --target-org MyOrg --path "/lightning/app/ThreatPulse"
```

---

## Project Structure

```
force-app/main/default/
├── classes/           # Apex service layer, controllers, batch jobs, tests
├── lwc/               # Lightning Web Components (threatList, threatDashboard, incidentTracker, iocViewer)
├── flows/             # 6 automation flows
├── objects/           # 7 custom objects with fields, validation rules, relationships
├── permissionsets/    # Admin, Analyst, ReadOnly
├── customMetadata/    # ThreatPulse_Config settings
├── triggers/          # Apex triggers
└── dashboards/        # Pre-built analytics dashboards
```

---

## License

MIT — free to use for portfolio and educational purposes.