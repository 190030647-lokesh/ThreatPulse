public with sharing class IncidentController {

    @AuraEnabled(cacheable=true)
    public static List<Incident__c> getIncidents() {
        return IncidentService.getAllIncidents();
    }

    @AuraEnabled
    public static void assignToMe(Id incidentId) {
        try {
            IncidentService.assignAnalyst(incidentId, UserInfo.getUserId());
        } catch (Exception e) {
            throw new AuraHandledException(e.getMessage());
        }
    }

    @AuraEnabled
    public static void resolveIncident(Id incidentId, String notes) {
        try {
            IncidentService.resolveIncident(incidentId, notes);
        } catch (Exception e) {
            throw new AuraHandledException(e.getMessage());
        }
    }

    @AuraEnabled
    public static void closeIncident(Id incidentId) {
        try {
            IncidentService.closeIncident(incidentId);
        } catch (Exception e) {
            throw new AuraHandledException(e.getMessage());
        }
    }
}
