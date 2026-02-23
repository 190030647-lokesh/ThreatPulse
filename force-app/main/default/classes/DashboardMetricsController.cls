public with sharing class DashboardMetricsController {

    public class DashboardMetrics {
        @AuraEnabled public Integer totalActiveThreats    { get; set; }
        @AuraEnabled public Integer criticalThreats       { get; set; }
        @AuraEnabled public Integer highThreats           { get; set; }
        @AuraEnabled public Integer openIncidents         { get; set; }
        @AuraEnabled public Integer totalIOCs             { get; set; }
        @AuraEnabled public List<SeverityCount> bySeverity { get; set; }
        @AuraEnabled public List<CategoryCount> byCategory { get; set; }
    }

    public class SeverityCount {
        @AuraEnabled public String label { get; set; }
        @AuraEnabled public Integer count { get; set; }
        public SeverityCount(String l, Integer c) { label = l; count = c; }
    }

    public class CategoryCount {
        @AuraEnabled public String label { get; set; }
        @AuraEnabled public Integer count { get; set; }
        public CategoryCount(String l, Integer c) { label = l; count = c; }
    }

    @AuraEnabled(cacheable=true)
    public static DashboardMetrics getMetrics() {
        DashboardMetrics metrics = new DashboardMetrics();

        // Total active threats
        metrics.totalActiveThreats = [
            SELECT COUNT() FROM Threat__c
            WHERE Is_Active__c = true
            WITH SECURITY_ENFORCED
        ];

        // Critical threats
        metrics.criticalThreats = [
            SELECT COUNT() FROM Threat__c
            WHERE Is_Active__c = true AND Severity__c = 'P1 - Critical'
            WITH SECURITY_ENFORCED
        ];

        // High threats
        metrics.highThreats = [
            SELECT COUNT() FROM Threat__c
            WHERE Is_Active__c = true AND Severity__c = 'P2 - High'
            WITH SECURITY_ENFORCED
        ];

        // Open incidents
        metrics.openIncidents = [
            SELECT COUNT() FROM Incident__c
            WHERE Status__c NOT IN ('Resolved', 'Closed')
            WITH SECURITY_ENFORCED
        ];

        // Total active IOCs
        metrics.totalIOCs = [
            SELECT COUNT() FROM Indicator_of_Compromise__c
            WHERE Is_Active__c = true
            WITH SECURITY_ENFORCED
        ];

        // By severity breakdown
        metrics.bySeverity = new List<SeverityCount>();
        for (AggregateResult ar : [
            SELECT Severity__c sev, COUNT(Id) cnt
            FROM Threat__c
            WHERE Is_Active__c = true
            WITH SECURITY_ENFORCED
            GROUP BY Severity__c
            ORDER BY COUNT(Id) DESC
        ]) {
            metrics.bySeverity.add(
                new SeverityCount((String) ar.get('sev'), (Integer) ar.get('cnt'))
            );
        }

        // By category breakdown
        metrics.byCategory = new List<CategoryCount>();
        for (AggregateResult ar : [
            SELECT Category__c cat, COUNT(Id) cnt
            FROM Threat__c
            WHERE Is_Active__c = true
            WITH SECURITY_ENFORCED
            GROUP BY Category__c
            ORDER BY COUNT(Id) DESC
        ]) {
            metrics.byCategory.add(
                new CategoryCount((String) ar.get('cat'), (Integer) ar.get('cnt'))
            );
        }

        return metrics;
    }

    @AuraEnabled(cacheable=true)
    public static List<Threat__c> getRecentThreats(Integer limitCount) {
        Integer lim = (limitCount != null && limitCount > 0) ? limitCount : 10;
        return [
            SELECT Id, Name, Severity__c, Status__c, Category__c,
                   Source__c, Detected_Date__c, Confidence_Score__c
            FROM Threat__c
            WHERE Is_Active__c = true
            WITH SECURITY_ENFORCED
            ORDER BY Detected_Date__c DESC
            LIMIT :lim
        ];
    }

    // Bug 5 fix: dashboard should show open/in-progress incidents only, not all historical incidents
    @AuraEnabled(cacheable=true)
    public static List<Incident__c> getRecentIncidents(Integer limitCount) {
        Integer lim = (limitCount != null && limitCount > 0) ? limitCount : 10;
        return [
            SELECT Id, Name, Status__c, Severity__c,
                   Threat__r.Name, Assigned_Analyst__r.Name,
                   Detected_Date__c, Resolved_Date__c
            FROM Incident__c
            WHERE Status__c NOT IN ('Resolved', 'Closed')
            WITH SECURITY_ENFORCED
            ORDER BY Detected_Date__c DESC
            LIMIT :lim
        ];
    }
}
