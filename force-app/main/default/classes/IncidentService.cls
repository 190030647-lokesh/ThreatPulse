public with sharing class IncidentService {

    // ─── Query Methods ──────────────────────────────────────────────────────────

    public static List<Incident__c> getAllIncidents() {
        return [
            SELECT Id, Name, Status__c, Severity__c, Threat__c, Threat__r.Name,
                   Assigned_Analyst__c, Assigned_Analyst__r.Name,
                   Detected_Date__c, Resolved_Date__c
            FROM Incident__c
            WITH SECURITY_ENFORCED
            ORDER BY Detected_Date__c DESC
            LIMIT 2000
        ];
    }

    public static List<Incident__c> getOpenIncidents() {
        return [
            SELECT Id, Name, Status__c, Severity__c, Threat__c, Threat__r.Name,
                   Assigned_Analyst__c, Assigned_Analyst__r.Name,
                   Detected_Date__c, Resolved_Date__c
            FROM Incident__c
            WHERE Status__c NOT IN ('Resolved', 'Closed')
            WITH SECURITY_ENFORCED
            ORDER BY Detected_Date__c DESC
        ];
    }

    public static Incident__c getIncidentById(Id incidentId) {
        List<Incident__c> results = [
            SELECT Id, Name, Status__c, Severity__c, Threat__c, Threat__r.Name,
                   Assigned_Analyst__c, Assigned_Analyst__r.Name,
                   Detected_Date__c, Resolved_Date__c, Resolution_Notes__c,
                   (SELECT Id, Asset__r.Name, Asset__r.Criticality__c, Impact_Level__c
                    FROM Incident_Assets__r)
            FROM Incident__c
            WHERE Id = :incidentId
            WITH SECURITY_ENFORCED
            LIMIT 1
        ];
        return results.isEmpty() ? null : results[0];
    }

    // ─── DML Methods ────────────────────────────────────────────────────────────

    public static Incident__c createIncident(Id threatId, String severity) {
        if (!Schema.sObjectType.Incident__c.isCreateable()) {
            throw new IncidentServiceException('Insufficient permissions to create Incident records.');
        }

        Incident__c incident = new Incident__c(
            Threat__c      = threatId,
            Severity__c    = severity,
            Status__c      = 'Open',
            Detected_Date__c = System.now()
        );
        insert incident;
        return incident;
    }

    public static void assignAnalyst(Id incidentId, Id analystId) {
        if (!Schema.sObjectType.Incident__c.isUpdateable()) {
            throw new IncidentServiceException('Insufficient permissions to update Incident records.');
        }
        update new Incident__c(
            Id                   = incidentId,
            Assigned_Analyst__c  = analystId,
            Status__c            = 'In Progress'
        );
    }

    public static void resolveIncident(Id incidentId, String resolutionNotes) {
        if (!Schema.sObjectType.Incident__c.isUpdateable()) {
            throw new IncidentServiceException('Insufficient permissions to update Incident records.');
        }
        update new Incident__c(
            Id                  = incidentId,
            Status__c           = 'Resolved',
            Resolution_Notes__c = resolutionNotes,
            Resolved_Date__c    = System.now()
        );
    }

    public static void closeIncident(Id incidentId) {
        if (!Schema.sObjectType.Incident__c.isUpdateable()) {
            throw new IncidentServiceException('Insufficient permissions to update Incident records.');
        }
        update new Incident__c(
            Id        = incidentId,
            Status__c = 'Closed'
        );
    }

    // ─── Auto-create from Threat ────────────────────────────────────────────────

    public static void autoCreateFromThreats(List<Threat__c> threats) {
        List<Incident__c> toInsert = new List<Incident__c>();
        for (Threat__c t : threats) {
            if (ThreatService.isCriticalOrHigh(t)) {
                toInsert.add(new Incident__c(
                    Threat__c        = t.Id,
                    Severity__c      = t.Severity__c,
                    Status__c        = 'Open',
                    Detected_Date__c = System.now()
                ));
            }
        }
        if (!toInsert.isEmpty()) {
            insert toInsert;
        }
    }

    // ─── MTTD / MTTR Helpers ────────────────────────────────────────────────────

    public static Decimal calculateMTTD(Incident__c incident) {
        if (incident.Detected_Date__c == null || incident.Threat__c == null) return null;
        return null; // Placeholder — will use Threat.Detected_Date__c in full impl
    }

    public static Decimal calculateMTTR(Incident__c incident) {
        if (incident.Detected_Date__c == null || incident.Resolved_Date__c == null) return null;
        Long ms = incident.Resolved_Date__c.getTime() - incident.Detected_Date__c.getTime();
        return ms / 3600000; // Return hours (Resolved - Detected = positive duration)
    }

    // ─── Custom Exception ───────────────────────────────────────────────────────

    public class IncidentServiceException extends Exception {}
}
