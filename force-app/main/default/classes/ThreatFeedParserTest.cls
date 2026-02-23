@IsTest
private class ThreatFeedParserTest {

    // ─── Custom JSON ─────────────────────────────────────────────────────────────

    @IsTest
    static void testParseCustomJson_validPayload() {
        Threat_Feed__c feed = new Threat_Feed__c(
            Name         = 'Test Feed',
            Feed_Type__c = 'Custom JSON',
            Feed_URL__c  = 'https://test.example.com/feed',
            Is_Active__c = true
        );
        insert feed;

        String body = JSON.serialize(new Map<String, Object>{
            'threats' => new List<Object>{
                new Map<String, Object>{
                    'name'     => 'TestThreat',
                    'severity' => 'P2 - High',
                    'category' => 'Malware',
                    'source'   => 'TestFeed',
                    'iocs'     => new List<Object>{
                        new Map<String, Object>{ 'type' => 'IP Address', 'value' => '1.2.3.4' },
                        new Map<String, Object>{ 'type' => 'Domain',     'value' => 'bad.com'  }
                    }
                }
            }
        });

        Test.startTest();
        ThreatFeedParser.ParseResult result = ThreatFeedParser.parse(feed, body);
        Test.stopTest();

        System.assertEquals(0, result.errors.size(), 'Should have no errors');
        System.assertEquals(1, result.threats.size(), 'Should parse 1 threat');
        System.assertEquals(2, result.iocs.size(),    'Should parse 2 IOCs');
        System.assertEquals('TestThreat',  result.threats[0].Name);
        System.assertEquals('P2 - High',   result.threats[0].Severity__c);
    }

    @IsTest
    static void testParseCustomJson_emptyThreats() {
        Threat_Feed__c feed = new Threat_Feed__c(
            Name         = 'Empty Feed',
            Feed_Type__c = 'Custom JSON',
            Feed_URL__c  = 'https://test.example.com/feed',
            Is_Active__c = true
        );
        insert feed;

        String body = '{"threats":[]}';

        Test.startTest();
        ThreatFeedParser.ParseResult result = ThreatFeedParser.parse(feed, body);
        Test.stopTest();

        System.assertEquals(0, result.threats.size());
        System.assertEquals(0, result.iocs.size());
    }

    @IsTest
    static void testParseCustomJson_malformed() {
        Threat_Feed__c feed = new Threat_Feed__c(
            Name         = 'Bad Feed',
            Feed_Type__c = 'Custom JSON',
            Feed_URL__c  = 'https://test.example.com/feed',
            Is_Active__c = true
        );
        insert feed;

        Test.startTest();
        ThreatFeedParser.ParseResult result = ThreatFeedParser.parse(feed, 'NOT_JSON{{{');
        Test.stopTest();

        System.assert(!result.errors.isEmpty(), 'Should capture parse error');
    }

    // ─── OTX ─────────────────────────────────────────────────────────────────────

    @IsTest
    static void testParseOTX_validPayload() {
        Threat_Feed__c feed = new Threat_Feed__c(
            Name         = 'OTX Feed',
            Feed_Type__c = 'OTX',
            Feed_URL__c  = 'https://otx.alienvault.com',
            Is_Active__c = true
        );
        insert feed;

        String body = JSON.serialize(new Map<String, Object>{
            'results' => new List<Object>{
                new Map<String, Object>{
                    'name'        => 'OTX Malware Pulse',
                    'description' => 'Bad actor',
                    'indicators'  => new List<Object>{
                        new Map<String, Object>{ 'type' => 'IPv4',   'indicator' => '5.5.5.5' },
                        new Map<String, Object>{ 'type' => 'domain', 'indicator' => 'otxbad.com' },
                        new Map<String, Object>{ 'type' => 'STIX_UNSUPPORTED', 'indicator' => 'x' }
                    }
                }
            }
        });

        Test.startTest();
        ThreatFeedParser.ParseResult result = ThreatFeedParser.parse(feed, body);
        Test.stopTest();

        System.assertEquals(1, result.threats.size());
        System.assertEquals(2, result.iocs.size(), 'STIX_UNSUPPORTED type should be skipped');
        System.assertEquals('OTX', result.threats[0].Source__c);
    }

    // ─── Null / Edge Cases ────────────────────────────────────────────────────────

    @IsTest
    static void testParseNullFeed() {
        Test.startTest();
        ThreatFeedParser.ParseResult result = ThreatFeedParser.parse(null, '{}');
        Test.stopTest();
        System.assert(!result.errors.isEmpty());
    }

    @IsTest
    static void testParseBlankBody() {
        Threat_Feed__c feed = new Threat_Feed__c(
            Name         = 'Blank Feed',
            Feed_Type__c = 'Custom JSON',
            Feed_URL__c  = 'https://test.example.com/feed',
            Is_Active__c = true
        );
        insert feed;

        Test.startTest();
        ThreatFeedParser.ParseResult result = ThreatFeedParser.parse(feed, '');
        Test.stopTest();
        System.assert(!result.errors.isEmpty());
    }

    @IsTest
    static void testUnsupportedFeedType() {
        Threat_Feed__c feed = new Threat_Feed__c(
            Name         = 'STIX Feed',
            Feed_Type__c = 'STIX/TAXII',
            Feed_URL__c  = 'https://cti-taxii.mitre.org',
            Is_Active__c = true
        );
        insert feed;

        Test.startTest();
        ThreatFeedParser.ParseResult result = ThreatFeedParser.parse(feed, '{"data":[]}');
        Test.stopTest();
        System.assert(!result.errors.isEmpty(), 'Unsupported type should log an error');
    }

    // ─── threatIOCMap correctness (multi-threat) ──────────────────────────────────

    @IsTest
    static void testParseCustomJson_multiThreat_IOCMapCorrect() {
        Threat_Feed__c feed = new Threat_Feed__c(
            Name         = 'Multi Feed',
            Feed_Type__c = 'Custom JSON',
            Feed_URL__c  = 'https://test.example.com/feed',
            Is_Active__c = true
        );
        insert feed;

        String body = JSON.serialize(new Map<String, Object>{
            'threats' => new List<Object>{
                new Map<String, Object>{
                    'name' => 'Threat A', 'severity' => 'P1 - Critical',
                    'category' => 'Malware', 'source' => 'Feed',
                    'iocs' => new List<Object>{
                        new Map<String, Object>{ 'type' => 'IP Address', 'value' => '1.1.1.1' }
                    }
                },
                new Map<String, Object>{
                    'name' => 'Threat B', 'severity' => 'P2 - High',
                    'category' => 'Phishing', 'source' => 'Feed',
                    'iocs' => new List<Object>{
                        new Map<String, Object>{ 'type' => 'Domain', 'value' => 'phish.com' },
                        new Map<String, Object>{ 'type' => 'URL',    'value' => 'http://phish.com/login' }
                    }
                }
            }
        });

        Test.startTest();
        ThreatFeedParser.ParseResult result = ThreatFeedParser.parse(feed, body);
        Test.stopTest();

        System.assertEquals(2, result.threats.size(), 'Should parse 2 threats');
        System.assertEquals(3, result.iocs.size(),    'Should parse 3 IOCs total');

        // Verify IOC map: threat 0 has 1 IOC, threat 1 has 2 IOCs
        System.assertEquals(1, result.threatIOCMap.get(0).size(), 'Threat A should have 1 IOC');
        System.assertEquals(2, result.threatIOCMap.get(1).size(), 'Threat B should have 2 IOCs');
        System.assertEquals('IP Address', result.threatIOCMap.get(0)[0].IOC_Type__c);
        System.assertEquals('Domain',     result.threatIOCMap.get(1)[0].IOC_Type__c);
    }

    // ─── OTX severity/category inference ─────────────────────────────────────────

    @IsTest
    static void testParseOTX_severityInference() {
        Threat_Feed__c feed = new Threat_Feed__c(
            Name         = 'OTX Inference Feed',
            Feed_Type__c = 'OTX',
            Feed_URL__c  = 'https://otx.alienvault.com',
            Is_Active__c = true
        );
        insert feed;

        String body = JSON.serialize(new Map<String, Object>{
            'results' => new List<Object>{
                new Map<String, Object>{ 'name' => 'APT Nation-State Campaign', 'description' => 'critical apt', 'indicators' => new List<Object>() },
                new Map<String, Object>{ 'name' => 'Ransomware outbreak',       'description' => 'high severity', 'indicators' => new List<Object>() },
                new Map<String, Object>{ 'name' => 'Generic phishing',          'description' => 'phishing kit',  'indicators' => new List<Object>() }
            }
        });

        Test.startTest();
        ThreatFeedParser.ParseResult result = ThreatFeedParser.parse(feed, body);
        Test.stopTest();

        System.assertEquals(3, result.threats.size());
        System.assertEquals('P1 - Critical', result.threats[0].Severity__c, 'APT should be Critical');
        System.assertEquals('P2 - High',     result.threats[1].Severity__c, 'Ransomware should be High');
        System.assertEquals('Phishing',      result.threats[2].Category__c, 'Should infer Phishing category');
    }
}
