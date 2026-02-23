@IsTest
private class ThreatFeedSyncBatchTest {

    // ─── Mock HTTP Callout ────────────────────────────────────────────────────────

    private class SuccessMock implements HttpCalloutMock {
        public HttpResponse respond(HttpRequest req) {
            HttpResponse res = new HttpResponse();
            res.setStatusCode(200);
            res.setBody(JSON.serialize(new Map<String, Object>{
                'threats' => new List<Object>{
                    new Map<String, Object>{
                        'name'     => 'Batch Threat',
                        'severity' => 'P3 - Medium',
                        'category' => 'Phishing',
                        'source'   => 'BatchTest',
                        'iocs'     => new List<Object>{
                            new Map<String, Object>{ 'type' => 'Domain', 'value' => 'batch-phish.com' }
                        }
                    }
                }
            }));
            return res;
        }
    }

    private class ErrorMock implements HttpCalloutMock {
        public HttpResponse respond(HttpRequest req) {
            HttpResponse res = new HttpResponse();
            res.setStatusCode(500);
            res.setBody('Internal Server Error');
            return res;
        }
    }

    // ─── Tests ───────────────────────────────────────────────────────────────────

    @IsTest
    static void testBatchSuccessSync() {
        Threat_Feed__c feed = new Threat_Feed__c(
            Name         = 'Batch Test Feed',
            Feed_URL__c  = 'https://example.com/feed',
            Feed_Type__c = 'Custom JSON',
            Is_Active__c = true
        );
        insert feed;

        Test.startTest();
        Test.setMock(HttpCalloutMock.class, new SuccessMock());
        Database.executeBatch(new ThreatFeedSyncBatch(), 1);
        Test.stopTest();

        Threat_Feed__c updated = [SELECT Status__c, Last_Sync__c FROM Threat_Feed__c WHERE Id = :feed.Id];
        System.assertEquals('Active', updated.Status__c, 'Feed status should be Active after success');
        System.assertNotEquals(null, updated.Last_Sync__c, 'Last_Sync__c should be set');

        System.assertEquals(1, [SELECT COUNT() FROM Threat__c WHERE Source__c = 'BatchTest']);
    }

    @IsTest
    static void testBatchHttpError() {
        Threat_Feed__c feed = new Threat_Feed__c(
            Name         = 'Error Feed',
            Feed_URL__c  = 'https://example.com/bad',
            Feed_Type__c = 'Custom JSON',
            Is_Active__c = true
        );
        insert feed;

        Test.startTest();
        Test.setMock(HttpCalloutMock.class, new ErrorMock());
        Database.executeBatch(new ThreatFeedSyncBatch(), 1);
        Test.stopTest();

        Threat_Feed__c updated = [SELECT Status__c, Last_Error__c FROM Threat_Feed__c WHERE Id = :feed.Id];
        System.assertEquals('Error', updated.Status__c, 'Feed should be marked Error on HTTP failure');
        System.assertNotEquals(null,  updated.Last_Error__c);
    }

    @IsTest
    static void testBatchSkipsInactiveFeeds() {
        Threat_Feed__c inactive = new Threat_Feed__c(
            Name         = 'Inactive Feed',
            Feed_URL__c  = 'https://example.com/inactive',
            Feed_Type__c = 'Custom JSON',
            Is_Active__c = false
        );
        insert inactive;

        Test.startTest();
        Test.setMock(HttpCalloutMock.class, new SuccessMock());
        Database.executeBatch(new ThreatFeedSyncBatch(), 50);
        Test.stopTest();

        // No threats should have been inserted since the feed is inactive
        System.assertEquals(0, [SELECT COUNT() FROM Threat__c]);
    }
}
