@IsTest
private class IncidentControllerTest {

    @TestSetup
    static void setup() {
        Threat__c t = new Threat__c(
            Name             = 'IC Ctrl Threat',
            Severity__c      = 'P1 - Critical',
            Status__c        = 'New',
            Category__c      = 'Malware',
            Source__c        = 'Unit Test',
            Is_Active__c     = true,
            Detected_Date__c = System.now()
        );
        insert t;
        insert new Incident__c(
            Threat__c        = t.Id,
            Severity__c      = 'P1 - Critical',
            Status__c        = 'Open',
            Detected_Date__c = System.now()
        );
    }

    // ─── getIncidents ─────────────────────────────────────────────────────────────

    @IsTest
    static void testGetIncidents() {
        Test.startTest();
        List<Incident__c> result = IncidentController.getIncidents();
        Test.stopTest();
        System.assert(result.size() >= 1, 'Should return at least the seeded incident');
    }

    // ─── assignToMe ───────────────────────────────────────────────────────────────

    @IsTest
    static void testAssignToMe() {
        Incident__c inc = [SELECT Id FROM Incident__c LIMIT 1];
        Test.startTest();
        IncidentController.assignToMe(inc.Id);
        Test.stopTest();
        Incident__c updated = [SELECT Assigned_Analyst__c, Status__c FROM Incident__c WHERE Id = :inc.Id];
        System.assertEquals(UserInfo.getUserId(), updated.Assigned_Analyst__c, 'Should be assigned to running user');
        System.assertEquals('In Progress', updated.Status__c, 'Status should move to In Progress');
    }

    @IsTest
    static void testAssignToMeInvalidIdThrowsAuraHandledException() {
        Test.startTest();
        try {
            IncidentController.assignToMe(null);
            System.assert(false, 'Expected AuraHandledException');
        } catch (AuraHandledException e) {
            System.assertNotEquals(null, e.getMessage());
        }
        Test.stopTest();
    }

    // ─── resolveIncident ──────────────────────────────────────────────────────────

    @IsTest
    static void testResolveIncident() {
        Incident__c inc = [SELECT Id FROM Incident__c LIMIT 1];
        Test.startTest();
        IncidentController.resolveIncident(inc.Id, 'Root cause identified and patched.');
        Test.stopTest();
        Incident__c updated = [SELECT Status__c, Resolution_Notes__c, Resolved_Date__c FROM Incident__c WHERE Id = :inc.Id];
        System.assertEquals('Resolved',                        updated.Status__c);
        System.assertEquals('Root cause identified and patched.', updated.Resolution_Notes__c);
        System.assertNotEquals(null, updated.Resolved_Date__c, 'Resolved date must be stamped');
    }

    @IsTest
    static void testResolveIncidentInvalidIdThrowsAuraHandledException() {
        Test.startTest();
        try {
            IncidentController.resolveIncident(null, 'Notes');
            System.assert(false, 'Expected AuraHandledException');
        } catch (AuraHandledException e) {
            System.assertNotEquals(null, e.getMessage());
        }
        Test.stopTest();
    }

    // ─── closeIncident ────────────────────────────────────────────────────────────

    @IsTest
    static void testCloseIncident() {
        Incident__c inc = [SELECT Id FROM Incident__c LIMIT 1];
        // Resolve first so validation rules allow closing
        IncidentController.resolveIncident(inc.Id, 'Resolved before close.');
        Test.startTest();
        IncidentController.closeIncident(inc.Id);
        Test.stopTest();
        System.assertEquals('Closed',
            [SELECT Status__c FROM Incident__c WHERE Id = :inc.Id].Status__c);
    }

    @IsTest
    static void testCloseIncidentInvalidIdThrowsAuraHandledException() {
        Test.startTest();
        try {
            IncidentController.closeIncident(null);
            System.assert(false, 'Expected AuraHandledException');
        } catch (AuraHandledException e) {
            System.assertNotEquals(null, e.getMessage());
        }
        Test.stopTest();
    }
}
