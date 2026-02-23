public with sharing class ThreatService {

    // ─── Query Methods ──────────────────────────────────────────────────────────

    public static List<Threat__c> getAllThreats() {
        return [
            SELECT Id, Name, Severity__c, Status__c, Category__c,
                   Source__c, Detected_Date__c, Confidence_Score__c, Is_Active__c
            FROM Threat__c
            WITH SECURITY_ENFORCED
            ORDER BY Detected_Date__c DESC
            LIMIT 2000
        ];
    }

    public static List<Threat__c> getActiveThreats() {
        return [
            SELECT Id, Name, Severity__c, Status__c, Category__c,
                   Source__c, Detected_Date__c, Confidence_Score__c, Is_Active__c
            FROM Threat__c
            WHERE Is_Active__c = true
            WITH SECURITY_ENFORCED
            ORDER BY Detected_Date__c DESC
        ];
    }

    public static List<Threat__c> getThreatsBySeverity(String severity) {
        return [
            SELECT Id, Name, Severity__c, Status__c, Category__c,
                   Source__c, Detected_Date__c, Confidence_Score__c, Is_Active__c
            FROM Threat__c
            WHERE Severity__c = :severity
            AND   Is_Active__c = true
            WITH SECURITY_ENFORCED
            ORDER BY Detected_Date__c DESC
        ];
    }

    public static Threat__c getThreatById(Id threatId) {
        List<Threat__c> results = [
            SELECT Id, Name, Severity__c, Status__c, Category__c,
                   Source__c, Description__c, Detected_Date__c,
                   Confidence_Score__c, Is_Active__c,
                   (SELECT Id, Name, IOC_Type__c, Value__c, Is_Active__c
                    FROM Indicators_of_Compromise__r)
            FROM Threat__c
            WHERE Id = :threatId
            WITH SECURITY_ENFORCED
            LIMIT 1
        ];
        return results.isEmpty() ? null : results[0];
    }

    // ─── DML Methods ────────────────────────────────────────────────────────────

    public static Threat__c createThreat(String name, String severity,
                                          String category, String source,
                                          String description) {
        if (!Schema.sObjectType.Threat__c.isCreateable()) {
            throw new ThreatServiceException('Insufficient permissions to create Threat records.');
        }

        Threat__c threat = new Threat__c(
            Name             = name,
            Severity__c      = severity,
            Category__c      = category,
            Source__c        = source,
            Description__c   = description,
            Status__c        = 'New',
            Is_Active__c     = true,
            Detected_Date__c = System.now()
        );
        insert threat;
        return threat;
    }

    public static void updateThreatStatus(Id threatId, String newStatus) {
        if (!Schema.sObjectType.Threat__c.isUpdateable()) {
            throw new ThreatServiceException('Insufficient permissions to update Threat records.');
        }

        Threat__c threat = new Threat__c(
            Id      = threatId,
            Status__c = newStatus
        );

        // Auto-deactivate when closed
        if (newStatus == 'Closed') {
            threat.Is_Active__c = false;
        }
        update threat;
    }

    public static void closeThreat(Id threatId) {
        updateThreatStatus(threatId, 'Closed');
    }

    public static void deleteThreat(Id threatId) {
        if (!Schema.sObjectType.Threat__c.isDeletable()) {
            throw new ThreatServiceException('Insufficient permissions to delete Threat records.');
        }
        delete new Threat__c(Id = threatId);
    }

    // ─── Scoring / Utility ──────────────────────────────────────────────────────

    public static Integer getSeverityScore(String severity) {
        Map<String, Integer> scoreMap = new Map<String, Integer>{
            'P1 - Critical' => 4,
            'P2 - High'     => 3,
            'P3 - Medium'   => 2,
            'P4 - Low'      => 1
        };
        return scoreMap.containsKey(severity) ? scoreMap.get(severity) : 0;
    }

    public static Boolean isCriticalOrHigh(Threat__c threat) {
        return threat.Severity__c == 'P1 - Critical' || threat.Severity__c == 'P2 - High';
    }

    // ─── Custom Exception ───────────────────────────────────────────────────────

    public class ThreatServiceException extends Exception {}
}
