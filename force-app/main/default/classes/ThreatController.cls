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
            Threat__c t = ThreatService.createThreat(name, severity, category, source, description);
            EventBus.publish(new ThreatPulse_Event__e(
                Event_Type__c = 'THREAT_CREATED',
                Record_Id__c  = String.valueOf(t.Id),
                Message__c    = 'New threat: ' + t.Name
            ));
            return t;
        } catch (Exception e) {
            throw new AuraHandledException(e.getMessage());
        }
    }

    @AuraEnabled
    public static void updateThreatStatus(Id threatId, String newStatus) {
        try {
            ThreatService.updateThreatStatus(threatId, newStatus);
            EventBus.publish(new ThreatPulse_Event__e(
                Event_Type__c = 'THREAT_UPDATED',
                Record_Id__c  = String.valueOf(threatId),
                Message__c    = 'Status changed to ' + newStatus
            ));
        } catch (Exception e) {
            throw new AuraHandledException(e.getMessage());
        }
    }

    @AuraEnabled
    public static void deleteThreat(Id threatId) {
        try {
            ThreatService.deleteThreat(threatId);
            EventBus.publish(new ThreatPulse_Event__e(
                Event_Type__c = 'THREAT_DELETED',
                Record_Id__c  = String.valueOf(threatId),
                Message__c    = 'Threat deleted'
            ));
        } catch (Exception e) {
            throw new AuraHandledException(e.getMessage());
        }
    }
}
