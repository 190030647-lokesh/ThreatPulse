public with sharing class ThreatFeedSyncBatch
    implements Database.Batchable<SObject>, Database.AllowsCallouts, Database.Stateful {

    // ─── State ──────────────────────────────────────────────────────────────────
    private List<String> errors    = new List<String>();
    private Integer      feedsSync = 0;
    private Integer      threatsSaved = 0;
    private Integer      iocsSaved    = 0;

    // ─── Batchable Interface ────────────────────────────────────────────────────

    public Database.QueryLocator start(Database.BatchableContext bc) {
        return Database.getQueryLocator([
            SELECT Id, Name, Feed_URL__c, Feed_Type__c, API_Key_Reference__c,
                   Sync_Frequency_Hours__c, Last_Sync__c
            FROM Threat_Feed__c
            WHERE Is_Active__c = true
            ORDER BY Last_Sync__c ASC NULLS FIRST
        ]);
    }

    public void execute(Database.BatchableContext bc, List<Threat_Feed__c> feeds) {
        for (Threat_Feed__c feed : feeds) {
            try {
                String body = callFeed(feed);
                if (String.isBlank(body)) {
                    errors.add(feed.Name + ': empty response');
                    continue;
                }

                ThreatFeedParser.ParseResult parsed = ThreatFeedParser.parse(feed, body);
                errors.addAll(parsed.errors);

                if (!parsed.threats.isEmpty()) {
                    List<Database.SaveResult> sr = Database.insert(parsed.threats, false);
                    // Collect errors but preserve original indices so threatIOCMap stays aligned
                    for (Integer i = 0; i < sr.size(); i++) {
                        if (!sr[i].isSuccess()) {
                            errors.add(feed.Name + ' threat insert error: ' + sr[i].getErrors()[0].getMessage());
                        } else {
                            threatsSaved++;
                        }
                    }

                    // Link IOCs to their parent threat using original index map.
                    // Skip any threat whose insert failed (Id will be null).
                    if (!parsed.threatIOCMap.isEmpty()) {
                        List<Indicator_of_Compromise__c> allIOCs = new List<Indicator_of_Compromise__c>();
                        for (Integer i = 0; i < parsed.threats.size(); i++) {
                            if (parsed.threats[i].Id == null) continue; // insert failed
                            List<Indicator_of_Compromise__c> iocList = parsed.threatIOCMap.get(i);
                            if (iocList != null && !iocList.isEmpty()) {
                                for (Indicator_of_Compromise__c ioc : iocList) {
                                    ioc.Threat__c = parsed.threats[i].Id;
                                }
                                allIOCs.addAll(iocList);
                            }
                        }
                        if (!allIOCs.isEmpty()) {
                            IOCService.upsertIOCs(allIOCs);
                            iocsSaved += allIOCs.size();
                        }
                    }
                }

                feed.Last_Sync__c = System.now();
                feed.Status__c    = 'Active';
                feed.Last_Error__c = null;
                feedsSync++;
            } catch (Exception e) {
                feed.Status__c     = 'Error';
                feed.Last_Error__c = e.getMessage().abbreviate(255);
                errors.add(feed.Name + ': ' + e.getMessage());
            }
        }
        update feeds;
    }

    public void finish(Database.BatchableContext bc) {
        System.debug(LoggingLevel.INFO,
            String.format('ThreatFeedSyncBatch complete. Feeds={0}, Threats={1}, IOCs={2}, Errors={3}',
                new List<Object>{ feedsSync, threatsSaved, iocsSaved, errors.size() }));
        if (!errors.isEmpty()) {
            System.debug(LoggingLevel.WARN, 'Errors: ' + String.join(errors, '\n'));
        }
    }

    // ─── HTTP Callout ────────────────────────────────────────────────────────────

    private String callFeed(Threat_Feed__c feed) {
        if (String.isBlank(feed.Feed_URL__c)) return null;

        HttpRequest req = new HttpRequest();
        req.setEndpoint(feed.Feed_URL__c);
        req.setMethod('GET');
        req.setTimeout(30000);

        // Bug 2 fix: use feed-type-appropriate auth header
        if (String.isNotBlank(feed.API_Key_Reference__c)) {
            if (feed.Feed_Type__c == 'OTX') {
                req.setHeader('X-OTX-API-KEY', feed.API_Key_Reference__c);
            } else {
                // Custom JSON and other feed types use standard Authorization Bearer
                req.setHeader('Authorization', 'Bearer ' + feed.API_Key_Reference__c);
            }
        }

        HttpResponse res = new Http().send(req);
        if (res.getStatusCode() == 200) {
            return res.getBody();
        }

        throw new ThreatFeedSyncException(
            'HTTP ' + res.getStatusCode() + ' from ' + feed.Feed_URL__c
        );
    }

    public class ThreatFeedSyncException extends Exception {}
}
