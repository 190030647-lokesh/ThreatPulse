@IsTest
private class ThreatServiceTest {

    // ─── Test Data Factory ──────────────────────────────────────────────────────
    private static Threat__c makeTestThreat(String severity) {
        return new Threat__c(
            Name             = 'Test Threat ' + severity,
            Severity__c      = severity,
            Status__c        = 'New',
            Category__c      = 'Malware',
            Source__c        = 'Unit Test',
            Is_Active__c     = true,
            Description__c   = 'Test threat description for unit testing.',
            Detected_Date__c = System.now()
        );
    }

    // ─── Tests ──────────────────────────────────────────────────────────────────

    @IsTest
    static void testCreateThreat() {
        Test.startTest();
        Threat__c t = ThreatService.createThreat(
            'New Threat', 'P1 - Critical', 'Malware', 'Unit Test', 'Desc'
        );
        Test.stopTest();

        System.assertNotEquals(null, t.Id, 'Threat should be inserted');
        List<Threat__c> results = [SELECT Status__c, Is_Active__c FROM Threat__c WHERE Id = :t.Id];
        System.assertEquals('New',  results[0].Status__c,   'Default status should be New');
        System.assertEquals(true,   results[0].Is_Active__c, 'Should be active');
    }

    @IsTest
    static void testGetAllThreats() {
        insert makeTestThreat('P2 - High');
        insert makeTestThreat('P3 - Medium');

        Test.startTest();
        List<Threat__c> threats = ThreatService.getAllThreats();
        Test.stopTest();

        System.assert(threats.size() >= 2, 'Should return at least 2 threats');
    }

    @IsTest
    static void testGetActiveThreats() {
        Threat__c active   = makeTestThreat('P2 - High');
        Threat__c inactive = makeTestThreat('P4 - Low');
        inactive.Is_Active__c = false;
        insert new List<Threat__c>{ active, inactive };

        Test.startTest();
        List<Threat__c> activeList = ThreatService.getActiveThreats();
        Test.stopTest();

        for (Threat__c t : activeList) {
            System.assertEquals(true, t.Is_Active__c, 'Only active threats returned');
        }
    }

    @IsTest
    static void testGetThreatsBySeverity() {
        insert makeTestThreat('P1 - Critical');

        Test.startTest();
        List<Threat__c> critical = ThreatService.getThreatsBySeverity('P1 - Critical');
        Test.stopTest();

        System.assert(!critical.isEmpty(), 'Should find P1 threats');
        for (Threat__c t : critical) {
            System.assertEquals('P1 - Critical', t.Severity__c);
        }
    }

    @IsTest
    static void testGetThreatById() {
        Threat__c t = makeTestThreat('P2 - High');
        insert t;

        Test.startTest();
        Threat__c result = ThreatService.getThreatById(t.Id);
        Test.stopTest();

        System.assertNotEquals(null, result);
        System.assertEquals(t.Id, result.Id);
    }

    @IsTest
    static void testGetThreatByIdNotFound() {
        Test.startTest();
        Threat__c result = ThreatService.getThreatById(null);
        Test.stopTest();
        System.assertEquals(null, result, 'Null ID should return null');
    }

    @IsTest
    static void testUpdateThreatStatus() {
        Threat__c t = makeTestThreat('P3 - Medium');
        insert t;

        Test.startTest();
        ThreatService.updateThreatStatus(t.Id, 'In Progress');
        Test.stopTest();

        Threat__c updated = [SELECT Status__c FROM Threat__c WHERE Id = :t.Id];
        System.assertEquals('In Progress', updated.Status__c);
    }

    @IsTest
    static void testCloseThreatDeactivates() {
        Threat__c t = makeTestThreat('P4 - Low');
        insert t;

        Test.startTest();
        ThreatService.closeThreat(t.Id);
        Test.stopTest();

        Threat__c closed = [SELECT Status__c, Is_Active__c FROM Threat__c WHERE Id = :t.Id];
        System.assertEquals('Closed', closed.Status__c);
        System.assertEquals(false,    closed.Is_Active__c, 'Closed threats should be deactivated');
    }

    @IsTest
    static void testDeleteThreat() {
        Threat__c t = makeTestThreat('P4 - Low');
        insert t;
        Id tid = t.Id;

        Test.startTest();
        ThreatService.deleteThreat(tid);
        Test.stopTest();

        System.assertEquals(0, [SELECT COUNT() FROM Threat__c WHERE Id = :tid]);
    }

    @IsTest
    static void testGetSeverityScore() {
        System.assertEquals(4, ThreatService.getSeverityScore('P1 - Critical'));
        System.assertEquals(3, ThreatService.getSeverityScore('P2 - High'));
        System.assertEquals(2, ThreatService.getSeverityScore('P3 - Medium'));
        System.assertEquals(1, ThreatService.getSeverityScore('P4 - Low'));
        System.assertEquals(0, ThreatService.getSeverityScore('Unknown'));
    }

    @IsTest
    static void testIsCriticalOrHigh() {
        Threat__c critical = new Threat__c(Severity__c = 'P1 - Critical');
        Threat__c high     = new Threat__c(Severity__c = 'P2 - High');
        Threat__c medium   = new Threat__c(Severity__c = 'P3 - Medium');

        System.assertEquals(true,  ThreatService.isCriticalOrHigh(critical));
        System.assertEquals(true,  ThreatService.isCriticalOrHigh(high));
        System.assertEquals(false, ThreatService.isCriticalOrHigh(medium));
    }
}
