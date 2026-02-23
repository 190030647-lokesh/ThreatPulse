@IsTest
private class IOCServiceTest {

    private static Threat__c makeTestThreat() {
        return new Threat__c(
            Name             = 'IOC Test Threat',
            Severity__c      = 'P2 - High',
            Status__c        = 'New',
            Category__c      = 'Malware',
            Source__c        = 'Unit Test',
            Is_Active__c     = true,
            Detected_Date__c = System.now()
        );
    }

    private static Indicator_of_Compromise__c makeIOC(Id threatId, String type, String value) {
        return new Indicator_of_Compromise__c(
            Threat__c     = threatId,
            IOC_Type__c   = type,
            Value__c      = value,
            Is_Active__c  = true,
            First_Seen__c = System.now(),
            Last_Seen__c  = System.now()
        );
    }

    // ─── Tests ──────────────────────────────────────────────────────────────────

    @IsTest
    static void testUpsertIOCsNewRecords() {
        Threat__c t = makeTestThreat();
        insert t;

        List<Indicator_of_Compromise__c> iocs = new List<Indicator_of_Compromise__c>{
            makeIOC(t.Id, 'IP Address', '10.0.0.1'),
            makeIOC(t.Id, 'Domain',     'evil.example.com')
        };

        Test.startTest();
        IOCService.upsertIOCs(iocs);
        Test.stopTest();

        System.assertEquals(2, [SELECT COUNT() FROM Indicator_of_Compromise__c WHERE Threat__c = :t.Id]);
    }

    @IsTest
    static void testUpsertIOCsDeduplicate() {
        Threat__c t = makeTestThreat();
        insert t;
        insert makeIOC(t.Id, 'IP Address', '10.0.0.2');

        // Upsert same IOC again
        List<Indicator_of_Compromise__c> iocs = new List<Indicator_of_Compromise__c>{
            makeIOC(t.Id, 'IP Address', '10.0.0.2')
        };

        Test.startTest();
        IOCService.upsertIOCs(iocs);
        Test.stopTest();

        // Should still be only 1
        System.assertEquals(1,
            [SELECT COUNT() FROM Indicator_of_Compromise__c
             WHERE Threat__c = :t.Id AND Value__c = '10.0.0.2']);
    }

    @IsTest
    static void testGetIOCsByThreat() {
        Threat__c t = makeTestThreat();
        insert t;
        insert makeIOC(t.Id, 'URL', 'http://bad.com');

        Test.startTest();
        List<Indicator_of_Compromise__c> results = IOCService.getIOCsByThreat(t.Id);
        Test.stopTest();

        System.assertEquals(1, results.size());
        System.assertEquals('http://bad.com', results[0].Value__c);
    }

    @IsTest
    static void testGetActiveIOCs() {
        Threat__c t = makeTestThreat();
        insert t;
        Indicator_of_Compromise__c active   = makeIOC(t.Id, 'Domain', 'active.com');
        Indicator_of_Compromise__c inactive = makeIOC(t.Id, 'Domain', 'inactive.com');
        inactive.Is_Active__c = false;
        insert new List<Indicator_of_Compromise__c>{ active, inactive };

        Test.startTest();
        List<Indicator_of_Compromise__c> activeList = IOCService.getActiveIOCs();
        Test.stopTest();

        for (Indicator_of_Compromise__c ioc : activeList) {
            System.assertEquals(true, ioc.Is_Active__c);
        }
    }

    @IsTest
    static void testSearchByValue() {
        Threat__c t = makeTestThreat();
        insert t;
        insert makeIOC(t.Id, 'Domain', 'searchable.evil.com');

        Test.startTest();
        List<Indicator_of_Compromise__c> results = IOCService.searchByValue('searchable');
        Test.stopTest();

        System.assert(!results.isEmpty());
        System.assert(results[0].Value__c.contains('searchable'));
    }

    @IsTest
    static void testDeactivateIOC() {
        Threat__c t = makeTestThreat();
        insert t;
        Indicator_of_Compromise__c ioc = makeIOC(t.Id, 'IP Address', '192.168.1.100');
        insert ioc;

        Test.startTest();
        IOCService.deactivateIOC(ioc.Id);
        Test.stopTest();

        System.assertEquals(false,
            [SELECT Is_Active__c FROM Indicator_of_Compromise__c WHERE Id = :ioc.Id].Is_Active__c);
    }

    @IsTest
    static void testDeactivateIOCsByThreat() {
        Threat__c t = makeTestThreat();
        insert t;
        insert new List<Indicator_of_Compromise__c>{
            makeIOC(t.Id, 'IP Address', '1.1.1.1'),
            makeIOC(t.Id, 'Domain',     'deactivate.com')
        };

        Test.startTest();
        IOCService.deactivateIOCsByThreat(t.Id);
        Test.stopTest();

        System.assertEquals(0,
            [SELECT COUNT() FROM Indicator_of_Compromise__c
             WHERE Threat__c = :t.Id AND Is_Active__c = true]);
    }
}
