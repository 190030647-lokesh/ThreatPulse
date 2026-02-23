public with sharing class IOCController {

    @AuraEnabled
    public static List<Indicator_of_Compromise__c> searchIOCs(String searchTerm) {
        try {
            if (String.isBlank(searchTerm)) {
                return IOCService.getActiveIOCs();
            }
            return IOCService.searchByValue(searchTerm);
        } catch (Exception e) {
            throw new AuraHandledException(e.getMessage());
        }
    }

    @AuraEnabled
    public static void deactivateIOC(Id iocId) {
        try {
            IOCService.deactivateIOC(iocId);
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
        } catch (AuraHandledException ahe) {
            throw ahe;
        } catch (Exception e) {
            throw new AuraHandledException(e.getMessage());
        }
    }
}
