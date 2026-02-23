public with sharing class IncidentController {

    @AuraEnabled(cacheable=true)
    public static List<Incident__c> getIncidents() {
        return IncidentService.getAllIncidents();
    }

    @AuraEnabled
    public static void assignToMe(Id incidentId) {
        try {
            IncidentService.assignAnalyst(incidentId, UserInfo.getUserId());
            EventBus.publish(new ThreatPulse_Event__e(
                Event_Type__c = 'INCIDENT_UPDATED',
                Record_Id__c  = String.valueOf(incidentId),
                Message__c    = 'Incident assigned'
            ));
        } catch (Exception e) {
            throw new AuraHandledException(e.getMessage());
        }
    }

    @AuraEnabled
    public static void resolveIncident(Id incidentId, String notes) {
        try {
            IncidentService.resolveIncident(incidentId, notes);
            EventBus.publish(new ThreatPulse_Event__e(
                Event_Type__c = 'INCIDENT_UPDATED',
                Record_Id__c  = String.valueOf(incidentId),
                Message__c    = 'Incident resolved'
            ));
        } catch (Exception e) {
            throw new AuraHandledException(e.getMessage());
        }
    }

    @AuraEnabled
    public static void closeIncident(Id incidentId) {
        try {
            IncidentService.closeIncident(incidentId);
            EventBus.publish(new ThreatPulse_Event__e(
                Event_Type__c = 'INCIDENT_UPDATED',
                Record_Id__c  = String.valueOf(incidentId),
                Message__c    = 'Incident closed'
            ));
        } catch (Exception e) {
            throw new AuraHandledException(e.getMessage());
        }
    }
}
