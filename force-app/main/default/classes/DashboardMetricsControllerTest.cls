@IsTest
private class DashboardMetricsControllerTest {

    private static void seedData() {
        List<Threat__c> threats = new List<Threat__c>{
            new Threat__c(Name='T1', Severity__c='P1 - Critical', Status__c='New',
                          Category__c='Malware',   Source__c='Test', Is_Active__c=true,
                          Detected_Date__c=System.now()),
            new Threat__c(Name='T2', Severity__c='P2 - High',     Status__c='In Progress',
                          Category__c='Phishing',  Source__c='Test', Is_Active__c=true,
                          Detected_Date__c=System.now()),
            new Threat__c(Name='T3', Severity__c='P3 - Medium',   Status__c='Closed',
                          Category__c='Ransomware', Source__c='Test', Is_Active__c=false,
                          Description__c='Closed threat for test data validation.',
                          Detected_Date__c=System.now())
        };
        insert threats;

        insert new Incident__c(
            Threat__c        = threats[0].Id,
            Severity__c      = 'P1 - Critical',
            Status__c        = 'Open',
            Detected_Date__c = System.now()
        );

        insert new Indicator_of_Compromise__c(
            Threat__c     = threats[0].Id,
            IOC_Type__c   = 'IP Address',
            Value__c      = '10.10.10.10',
            Is_Active__c  = true,
            First_Seen__c = System.now(),
            Last_Seen__c  = System.now()
        );
    }

    // ─── Tests ───────────────────────────────────────────────────────────────────

    @IsTest
    static void testGetMetrics() {
        seedData();

        Test.startTest();
        DashboardMetricsController.DashboardMetrics m = DashboardMetricsController.getMetrics();
        Test.stopTest();

        System.assertEquals(2,  m.totalActiveThreats, '2 active threats (T1, T2)');
        System.assertEquals(1,  m.criticalThreats,    '1 critical threat');
        System.assertEquals(1,  m.highThreats,        '1 high threat');
        System.assertEquals(1,  m.openIncidents,      '1 open incident');
        System.assertEquals(1,  m.totalIOCs,          '1 active IOC');
        System.assertNotEquals(null, m.bySeverity);
        System.assertNotEquals(null, m.byCategory);
        System.assert(m.bySeverity.size() >= 1);
        System.assert(m.byCategory.size() >= 1);
    }

    @IsTest
    static void testGetRecentThreats() {
        seedData();

        Test.startTest();
        List<Threat__c> recent = DashboardMetricsController.getRecentThreats(5);
        Test.stopTest();

        System.assert(!recent.isEmpty());
        System.assert(recent.size() <= 5);
    }

    @IsTest
    static void testGetRecentThreatsDefaultLimit() {
        seedData();

        Test.startTest();
        List<Threat__c> recent = DashboardMetricsController.getRecentThreats(null);
        Test.stopTest();

        System.assertNotEquals(null, recent);
    }

    @IsTest
    static void testGetRecentIncidents() {
        seedData();

        Test.startTest();
        List<Incident__c> recent = DashboardMetricsController.getRecentIncidents(5);
        Test.stopTest();

        System.assert(!recent.isEmpty());
        System.assert(recent.size() <= 5);
    }

    @IsTest
    static void testGetRecentIncidentsDefaultLimit() {
        seedData();

        Test.startTest();
        List<Incident__c> recent = DashboardMetricsController.getRecentIncidents(0);
        Test.stopTest();

        System.assertNotEquals(null, recent);
    }
}
