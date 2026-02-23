@IsTest
private class IncidentServiceTest {

    private static Threat__c makeTestThreat(String severity) {
        return new Threat__c(
            Name             = 'Test Threat',
            Severity__c      = severity,
            Status__c        = 'New',
            Category__c      = 'Malware',
            Source__c        = 'Unit Test',
            Is_Active__c     = true,
            Detected_Date__c = System.now()
        );
    }

    // ─── Tests ──────────────────────────────────────────────────────────────────

    @IsTest
    static void testCreateIncident() {
        Threat__c t = makeTestThreat('P1 - Critical');
        insert t;

        Test.startTest();
        Incident__c inc = IncidentService.createIncident(t.Id, 'P1 - Critical');
        Test.stopTest();

        System.assertNotEquals(null, inc.Id);
        Incident__c saved = [SELECT Status__c, Severity__c FROM Incident__c WHERE Id = :inc.Id];
        System.assertEquals('Open',         saved.Status__c);
        System.assertEquals('P1 - Critical', saved.Severity__c);
    }

    @IsTest
    static void testAssignAnalyst() {
        Threat__c t = makeTestThreat('P2 - High');
        insert t;
        Incident__c inc = IncidentService.createIncident(t.Id, 'P2 - High');
        Id userId = UserInfo.getUserId();

        Test.startTest();
        IncidentService.assignAnalyst(inc.Id, userId);
        Test.stopTest();

        Incident__c updated = [SELECT Status__c, Assigned_Analyst__c FROM Incident__c WHERE Id = :inc.Id];
        System.assertEquals('In Progress', updated.Status__c);
        System.assertEquals(userId,        updated.Assigned_Analyst__c);
    }

    @IsTest
    static void testResolveIncident() {
        Threat__c t = makeTestThreat('P3 - Medium');
        insert t;
        Incident__c inc = IncidentService.createIncident(t.Id, 'P3 - Medium');

        Test.startTest();
        IncidentService.resolveIncident(inc.Id, 'Patched the system.');
        Test.stopTest();

        Incident__c resolved = [SELECT Status__c, Resolution_Notes__c, Resolved_Date__c
                                 FROM Incident__c WHERE Id = :inc.Id];
        System.assertEquals('Resolved',           resolved.Status__c);
        System.assertEquals('Patched the system.', resolved.Resolution_Notes__c);
        System.assertNotEquals(null,               resolved.Resolved_Date__c);
    }

    @IsTest
    static void testCloseIncident() {
        Threat__c t = makeTestThreat('P4 - Low');
        insert t;
        Incident__c inc = IncidentService.createIncident(t.Id, 'P4 - Low');

        inc.Resolution_Notes__c = 'Test resolution notes for closure validation.';
        update inc;

        Test.startTest();
        IncidentService.closeIncident(inc.Id);
        Test.stopTest();

        System.assertEquals('Closed',
            [SELECT Status__c FROM Incident__c WHERE Id = :inc.Id].Status__c);
    }

    @IsTest
    static void testGetAllIncidents() {
        Threat__c t = makeTestThreat('P2 - High');
        insert t;
        IncidentService.createIncident(t.Id, 'P2 - High');

        Test.startTest();
        List<Incident__c> all = IncidentService.getAllIncidents();
        Test.stopTest();

        System.assert(all.size() >= 1);
    }

    @IsTest
    static void testGetOpenIncidents() {
        Threat__c t = makeTestThreat('P2 - High');
        insert t;
        Incident__c open   = IncidentService.createIncident(t.Id, 'P2 - High');
        Incident__c closed = IncidentService.createIncident(t.Id, 'P2 - High');
        closed.Resolution_Notes__c = 'Test resolution notes for closure validation.';
        update closed;
        IncidentService.closeIncident(closed.Id);

        Test.startTest();
        List<Incident__c> openList = IncidentService.getOpenIncidents();
        Test.stopTest();

        for (Incident__c inc : openList) {
            System.assertNotEquals('Closed', inc.Status__c);
        }
    }

    @IsTest
    static void testAutoCreateFromThreats() {
        List<Threat__c> threats = new List<Threat__c>{
            makeTestThreat('P1 - Critical'),
            makeTestThreat('P2 - High'),
            makeTestThreat('P4 - Low')
        };
        insert threats;

        Test.startTest();
        IncidentService.autoCreateFromThreats(threats);
        Test.stopTest();

        Integer count = [SELECT COUNT() FROM Incident__c
                         WHERE Threat__c IN :new List<Id>{ threats[0].Id, threats[1].Id }];
        System.assertEquals(2, count, 'Should auto-create incidents for P1 and P2 only');
    }

    @IsTest
    static void testCalculateMTTR() {
        Incident__c inc = new Incident__c();
        inc.Detected_Date__c = System.now().addHours(-5);
        inc.Resolved_Date__c = System.now();

        Test.startTest();
        Decimal hours = IncidentService.calculateMTTR(inc);
        Test.stopTest();

        System.assertNotEquals(null, hours);
        System.assert(hours >= 4, 'MTTR should be roughly 5 hours');
    }
}
