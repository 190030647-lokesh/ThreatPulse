public with sharing class IOCController {

    // cacheable=true enables @wire reactive binding in LWC for automatic cache invalidation
    // Bug 7 fix: typeFilter added for server-side IOC type filtering
    @AuraEnabled(cacheable=true)
    public static List<Indicator_of_Compromise__c> searchIOCs(String searchTerm, String activeFilter, String typeFilter) {
        try {
            if (String.isBlank(searchTerm)) {
                return IOCService.getIOCsFiltered(activeFilter, typeFilter);
            }
            // activeFilter and typeFilter are applied server-side
            return IOCService.searchByValue(searchTerm, activeFilter, typeFilter);
        } catch (Exception e) {
            throw new AuraHandledException(e.getMessage());
        }
    }

    @AuraEnabled
    public static void deactivateIOC(Id iocId) {
        try {
            IOCService.deactivateIOC(iocId);
            EventBus.publish(new ThreatPulse_Event__e(
                Event_Type__c = 'IOC_DEACTIVATED',
                Record_Id__c  = String.valueOf(iocId),
                Message__c    = 'IOC deactivated'
            ));
        } catch (Exception e) {
            throw new AuraHandledException(e.getMessage());
        }
    }

    @AuraEnabled
    public static void deactivateIOCList(List<Id> iocIds) {
        try {
            if (!Schema.sObjectType.Indicator_of_Compromise__c.isUpdateable()) {
                throw new AuraHandledException('Insufficient permissions to update IOC records.');
            }
            List<Indicator_of_Compromise__c> toUpdate = new List<Indicator_of_Compromise__c>();
            for (Id iocId : iocIds) {
                toUpdate.add(new Indicator_of_Compromise__c(Id = iocId, Is_Active__c = false));
            }
            update toUpdate;
            // Bug 5 fix: use 'BULK' sentinel instead of null so consumers can distinguish bulk vs single
            EventBus.publish(new ThreatPulse_Event__e(
                Event_Type__c = 'IOC_DEACTIVATED',
                Record_Id__c  = 'BULK',
                Message__c    = iocIds.size() + ' IOC(s) deactivated'
            ));
        } catch (AuraHandledException ahe) {
            throw ahe;
        } catch (Exception e) {
            throw new AuraHandledException(e.getMessage());
        }
    }
}
