public with sharing class ThreatController {

    @AuraEnabled(cacheable=true)
    public static List<Threat__c> getThreats() {
        return ThreatService.getAllThreats();
    }

    @AuraEnabled
    public static Threat__c createThreat(
        String name, String severity, String category,
        String source, String description
    ) {
        try {
            return ThreatService.createThreat(name, severity, category, source, description);
        } catch (Exception e) {
            throw new AuraHandledException(e.getMessage());
        }
    }

    @AuraEnabled
    public static void updateThreatStatus(Id threatId, String newStatus) {
        try {
            ThreatService.updateThreatStatus(threatId, newStatus);
        } catch (Exception e) {
            throw new AuraHandledException(e.getMessage());
        }
    }

    @AuraEnabled
    public static void deleteThreat(Id threatId) {
        try {
            ThreatService.deleteThreat(threatId);
        } catch (Exception e) {
            throw new AuraHandledException(e.getMessage());
        }
    }
}
