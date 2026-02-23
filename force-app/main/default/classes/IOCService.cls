public with sharing class IOCService {

    // ─── Query Methods ──────────────────────────────────────────────────────────

    public static List<Indicator_of_Compromise__c> getIOCsByThreat(Id threatId) {
        return [
            SELECT Id, Name, IOC_Type__c, Value__c, Description__c,
                   First_Seen__c, Last_Seen__c, Is_Active__c, Confidence__c
            FROM Indicator_of_Compromise__c
            WHERE Threat__c = :threatId
            WITH SECURITY_ENFORCED
            ORDER BY IOC_Type__c, Value__c
        ];
    }

    public static List<Indicator_of_Compromise__c> getActiveIOCs() {
        return [
            SELECT Id, Name, IOC_Type__c, Value__c, Threat__c, Threat__r.Name,
                   First_Seen__c, Last_Seen__c, Confidence__c, Is_Active__c
            FROM Indicator_of_Compromise__c
            WHERE Is_Active__c = true
            WITH SECURITY_ENFORCED
            ORDER BY Last_Seen__c DESC
            LIMIT 1000
        ];
    }

    // Returns IOCs filtered by active status — used when search term is blank
    public static List<Indicator_of_Compromise__c> getIOCsFiltered(String activeFilter) {
        if (activeFilter == 'false') {
            return [
                SELECT Id, Name, IOC_Type__c, Value__c, Threat__c, Threat__r.Name,
                       First_Seen__c, Last_Seen__c, Confidence__c, Is_Active__c
                FROM Indicator_of_Compromise__c
                WHERE Is_Active__c = false
                WITH SECURITY_ENFORCED
                ORDER BY Last_Seen__c DESC NULLS LAST
                LIMIT 1000
            ];
        } else if (activeFilter == 'all') {
            return [
                SELECT Id, Name, IOC_Type__c, Value__c, Threat__c, Threat__r.Name,
                       First_Seen__c, Last_Seen__c, Confidence__c, Is_Active__c
                FROM Indicator_of_Compromise__c
                WITH SECURITY_ENFORCED
                ORDER BY Last_Seen__c DESC NULLS LAST
                LIMIT 1000
            ];
        }
        // Default: active only
        return getActiveIOCs();
    }

    public static List<Indicator_of_Compromise__c> searchByValue(String searchVal) {
        String likeVal = '%' + searchVal + '%';
        return [
            SELECT Id, Name, IOC_Type__c, Value__c, Threat__c, Threat__r.Name,
                   Is_Active__c, Confidence__c, First_Seen__c, Last_Seen__c
            FROM Indicator_of_Compromise__c
            WHERE Value__c LIKE :likeVal
            WITH SECURITY_ENFORCED
            LIMIT 200
        ];
    }

    // ─── DML Methods ────────────────────────────────────────────────────────────

    public static void upsertIOCs(List<Indicator_of_Compromise__c> iocs) {
        if (!Schema.sObjectType.Indicator_of_Compromise__c.isCreateable() ||
            !Schema.sObjectType.Indicator_of_Compromise__c.isUpdateable()) {
            throw new IOCServiceException('Insufficient permissions to upsert IOC records.');
        }

        // Deduplicate by Value__c + IOC_Type__c
        Map<String, Indicator_of_Compromise__c> existing = getExistingIOCMap(iocs);
        List<Indicator_of_Compromise__c> toUpsert = new List<Indicator_of_Compromise__c>();

        for (Indicator_of_Compromise__c ioc : iocs) {
            String key = ioc.IOC_Type__c + '_' + ioc.Value__c;
            if (existing.containsKey(key)) {
                Indicator_of_Compromise__c ex = existing.get(key);
                ex.Last_Seen__c  = System.now();
                ex.Is_Active__c  = true;
                if (ioc.Confidence__c != null) ex.Confidence__c = ioc.Confidence__c;
                toUpsert.add(ex);
            } else {
                if (ioc.First_Seen__c == null) ioc.First_Seen__c = System.now();
                if (ioc.Last_Seen__c  == null) ioc.Last_Seen__c  = System.now();
                toUpsert.add(ioc);
            }
        }
        upsert toUpsert;
    }

    public static void deactivateIOC(Id iocId) {
        if (!Schema.sObjectType.Indicator_of_Compromise__c.isUpdateable()) {
            throw new IOCServiceException('Insufficient permissions to update IOC records.');
        }
        update new Indicator_of_Compromise__c(Id = iocId, Is_Active__c = false);
    }

    public static void deactivateIOCsByThreat(Id threatId) {
        if (!Schema.sObjectType.Indicator_of_Compromise__c.isUpdateable()) {
            throw new IOCServiceException('Insufficient permissions to update IOC records.');
        }
        List<Indicator_of_Compromise__c> iocs = [
            SELECT Id FROM Indicator_of_Compromise__c
            WHERE Threat__c = :threatId AND Is_Active__c = true
            WITH SECURITY_ENFORCED
        ];
        for (Indicator_of_Compromise__c ioc : iocs) {
            ioc.Is_Active__c = false;
        }
        update iocs;
    }

    // ─── Private Helpers ────────────────────────────────────────────────────────

    private static Map<String, Indicator_of_Compromise__c> getExistingIOCMap(
        List<Indicator_of_Compromise__c> iocs
    ) {
        Set<String> values = new Set<String>();
        for (Indicator_of_Compromise__c ioc : iocs) {
            values.add(ioc.Value__c);
        }

        Map<String, Indicator_of_Compromise__c> result = new Map<String, Indicator_of_Compromise__c>();
        for (Indicator_of_Compromise__c ex : [
            SELECT Id, IOC_Type__c, Value__c, Confidence__c, Last_Seen__c, Is_Active__c
            FROM Indicator_of_Compromise__c
            WHERE Value__c IN :values
            WITH SECURITY_ENFORCED
        ]) {
            result.put(ex.IOC_Type__c + '_' + ex.Value__c, ex);
        }
        return result;
    }

    // ─── Custom Exception ───────────────────────────────────────────────────────

    public class IOCServiceException extends Exception {}
}
