@IsTest
private class ThreatControllerTest {

    @TestSetup
    static void setup() {
        insert new Threat__c(
            Name             = 'Ctrl Test Threat',
            Severity__c      = 'P2 - High',
            Status__c        = 'New',
            Category__c      = 'Malware',
            Source__c        = 'Unit Test',
            Is_Active__c     = true,
            Detected_Date__c = System.now()
        );
    }

    // ─── getThreats ──────────────────────────────────────────────────────────────

    @IsTest
    static void testGetThreats() {
        Test.startTest();
        List<Threat__c> result = ThreatController.getThreats();
        Test.stopTest();
        System.assert(result.size() >= 1, 'Should return at least the seeded threat');
    }

    // ─── createThreat ─────────────────────────────────────────────────────────────

    @IsTest
    static void testCreateThreat() {
        Test.startTest();
        Threat__c t = ThreatController.createThreat(
            'New Ctrl Threat', 'P1 - Critical', 'Ransomware', 'FeedX', 'Test description'
        );
        Test.stopTest();
        System.assertNotEquals(null, t.Id, 'Returned threat must have an Id');
        Threat__c persisted = [SELECT Status__c, Is_Active__c, Severity__c FROM Threat__c WHERE Id = :t.Id];
        System.assertEquals('New',          persisted.Status__c,   'Default status should be New');
        System.assertEquals(true,          persisted.Is_Active__c, 'Should be active');
        System.assertEquals('P1 - Critical', persisted.Severity__c);
    }

    @IsTest
    static void testCreateThreatMissingNameThrowsAuraHandledException() {
        Test.startTest();
        try {
            ThreatController.createThreat(null, null, null, null, null);
            System.assert(false, 'Expected AuraHandledException');
        } catch (AuraHandledException e) {
            System.assertNotEquals(null, e.getMessage(), 'Exception message should not be null');
        }
        Test.stopTest();
    }

    // ─── updateThreatStatus ───────────────────────────────────────────────────────

    @IsTest
    static void testUpdateThreatStatusContained() {
        Threat__c t = [SELECT Id FROM Threat__c LIMIT 1];
        Test.startTest();
        ThreatController.updateThreatStatus(t.Id, 'Contained');
        Test.stopTest();
        System.assertEquals('Contained',
            [SELECT Status__c FROM Threat__c WHERE Id = :t.Id].Status__c);
    }

    @IsTest
    static void testUpdateThreatStatusClosed_DeactivatesThreat() {
        Threat__c t = [SELECT Id FROM Threat__c LIMIT 1];
        Test.startTest();
        ThreatController.updateThreatStatus(t.Id, 'Closed');
        Test.stopTest();
        Threat__c closed = [SELECT Status__c, Is_Active__c FROM Threat__c WHERE Id = :t.Id];
        System.assertEquals('Closed', closed.Status__c);
        System.assertEquals(false,    closed.Is_Active__c, 'Closed threats must be deactivated');
    }

    @IsTest
    static void testUpdateThreatStatusInvalidIdThrowsAuraHandledException() {
        Test.startTest();
        try {
            ThreatController.updateThreatStatus(null, 'Closed');
            System.assert(false, 'Expected AuraHandledException');
        } catch (AuraHandledException e) {
            System.assertNotEquals(null, e.getMessage());
        }
        Test.stopTest();
    }

    // ─── deleteThreat ────────────────────────────────────────────────────────────

    @IsTest
    static void testDeleteThreat() {
        Threat__c t = [SELECT Id FROM Threat__c LIMIT 1];
        Id tid = t.Id;
        Test.startTest();
        ThreatController.deleteThreat(tid);
        Test.stopTest();
        System.assertEquals(0, [SELECT COUNT() FROM Threat__c WHERE Id = :tid]);
    }

    @IsTest
    static void testDeleteThreatInvalidIdThrowsAuraHandledException() {
        Test.startTest();
        try {
            ThreatController.deleteThreat(null);
            System.assert(false, 'Expected AuraHandledException');
        } catch (AuraHandledException e) {
            System.assertNotEquals(null, e.getMessage());
        }
        Test.stopTest();
    }
}
