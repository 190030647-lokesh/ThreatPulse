@IsTest
private class IOCControllerTest {

    @TestSetup
    static void setup() {
        Threat__c t = new Threat__c(
            Name             = 'IOC Ctrl Threat',
            Severity__c      = 'P2 - High',
            Status__c        = 'New',
            Category__c      = 'Malware',
            Source__c        = 'Unit Test',
            Is_Active__c     = true,
            Detected_Date__c = System.now()
        );
        insert t;
        insert new List<Indicator_of_Compromise__c>{
            new Indicator_of_Compromise__c(
                Threat__c     = t.Id,
                IOC_Type__c   = 'IP Address',
                Value__c      = '192.168.99.1',
                Is_Active__c  = true,
                First_Seen__c = System.now(),
                Last_Seen__c  = System.now()
            ),
            new Indicator_of_Compromise__c(
                Threat__c     = t.Id,
                IOC_Type__c   = 'Domain',
                Value__c      = 'inactive-ctrl.example.com',
                Is_Active__c  = false,
                First_Seen__c = System.now(),
                Last_Seen__c  = System.now()
            )
        };
    }

    // ─── searchIOCs — blank term (delegates to getIOCsFiltered) ──────────────────

    @IsTest
    static void testSearchIOCsBlankTermActiveFilter() {
        Test.startTest();
        List<Indicator_of_Compromise__c> result = IOCController.searchIOCs('', 'true', '');
        Test.stopTest();
        System.assert(result.size() >= 1, 'Should return active IOCs');
        for (Indicator_of_Compromise__c ioc : result) {
            System.assertEquals(true, ioc.Is_Active__c, 'Active filter must return only active IOCs');
        }
    }

    @IsTest
    static void testSearchIOCsBlankTermInactiveFilter() {
        Test.startTest();
        List<Indicator_of_Compromise__c> result = IOCController.searchIOCs('', 'false', '');
        Test.stopTest();
        System.assert(result.size() >= 1, 'Should return inactive IOCs');
        for (Indicator_of_Compromise__c ioc : result) {
            System.assertEquals(false, ioc.Is_Active__c, 'Inactive filter must return only inactive IOCs');
        }
    }

    @IsTest
    static void testSearchIOCsBlankTermAllFilter() {
        Test.startTest();
        List<Indicator_of_Compromise__c> result = IOCController.searchIOCs('', 'all', '');
        Test.stopTest();
        System.assert(result.size() >= 2, '"All" filter should return both active and inactive IOCs');
    }

    // ─── searchIOCs — non-blank term (delegates to searchByValue with activeFilter) ─

    @IsTest
    static void testSearchIOCsByValueActiveOnly() {
        Test.startTest();
        List<Indicator_of_Compromise__c> result = IOCController.searchIOCs('192.168', 'true', '');
        Test.stopTest();
        System.assert(result.size() >= 1, 'Should find active IP IOC by value fragment');
        for (Indicator_of_Compromise__c ioc : result) {
            System.assertEquals(true, ioc.Is_Active__c, 'Must only return active records');
        }
    }

    @IsTest
    static void testSearchIOCsByValueInactiveOnly() {
        Test.startTest();
        List<Indicator_of_Compromise__c> result = IOCController.searchIOCs('inactive-ctrl', 'false', '');
        Test.stopTest();
        System.assert(!result.isEmpty(), 'Should find inactive domain IOC by value fragment');
        for (Indicator_of_Compromise__c ioc : result) {
            System.assertEquals(false, ioc.Is_Active__c, 'Must only return inactive records');
        }
    }

    @IsTest
    static void testSearchIOCsByValueAllFilter() {
        Test.startTest();
        List<Indicator_of_Compromise__c> result = IOCController.searchIOCs('example', 'all', '');
        Test.stopTest();
        // Should find at least the inactive domain (value contains 'example')
        System.assert(!result.isEmpty(), 'All filter with search term should find matching IOCs');
    }

    // ─── deactivateIOC ────────────────────────────────────────────────────────────

    @IsTest
    static void testDeactivateIOC() {
        Indicator_of_Compromise__c ioc =
            [SELECT Id FROM Indicator_of_Compromise__c WHERE Is_Active__c = true LIMIT 1];
        Test.startTest();
        IOCController.deactivateIOC(ioc.Id);
        Test.stopTest();
        System.assertEquals(false,
            [SELECT Is_Active__c FROM Indicator_of_Compromise__c WHERE Id = :ioc.Id].Is_Active__c,
            'IOC should be deactivated');
    }

    // ─── deactivateIOCList ────────────────────────────────────────────────────────

    @IsTest
    static void testDeactivateIOCList() {
        List<Indicator_of_Compromise__c> active =
            [SELECT Id FROM Indicator_of_Compromise__c WHERE Is_Active__c = true];
        List<Id> ids = new List<Id>();
        for (Indicator_of_Compromise__c ioc : active) { ids.add(ioc.Id); }

        Test.startTest();
        IOCController.deactivateIOCList(ids);
        Test.stopTest();

        System.assertEquals(0,
            [SELECT COUNT() FROM Indicator_of_Compromise__c
             WHERE Id IN :ids AND Is_Active__c = true],
            'All targeted IOCs should be deactivated');
    }

    @IsTest
    static void testDeactivateIOCListEmpty() {
        // Should complete without error on empty list
        Test.startTest();
        IOCController.deactivateIOCList(new List<Id>());
        Test.stopTest();
        System.assert(true, 'Empty list should not throw');
    }
}
