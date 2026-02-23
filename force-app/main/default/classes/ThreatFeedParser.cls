public with sharing class ThreatFeedParser {

    // ─── Result Wrapper ─────────────────────────────────────────────────────────

    public class ParseResult {
        public List<Threat__c>                                  threats      { get; set; }
        public List<Indicator_of_Compromise__c>                 iocs         { get; set; }
        // Maps threat list index → its IOCs so each IOC links to the correct parent threat
        public Map<Integer, List<Indicator_of_Compromise__c>>  threatIOCMap { get; set; }
        public List<String>                                     errors       { get; set; }

        public ParseResult() {
            threats      = new List<Threat__c>();
            iocs         = new List<Indicator_of_Compromise__c>();
            threatIOCMap = new Map<Integer, List<Indicator_of_Compromise__c>>();
            errors       = new List<String>();
        }
    }

    // ─── Dispatcher ─────────────────────────────────────────────────────────────

    public static ParseResult parse(Threat_Feed__c feed, String rawBody) {
        if (feed == null || String.isBlank(rawBody)) {
            ParseResult empty = new ParseResult();
            empty.errors.add('Feed config or body is null/blank');
            return empty;
        }

        String feedType = feed.Feed_Type__c;
        if (feedType == 'Custom JSON') return parseCustomJson(feed, rawBody);
        if (feedType == 'OTX')         return parseOTX(feed, rawBody);

        // STIX / TAXII / MISP / VirusTotal — stub for future expansion
        ParseResult res = new ParseResult();
        res.errors.add('Feed type not yet supported: ' + feedType);
        return res;
    }

    // ─── Custom JSON Parser ─────────────────────────────────────────────────────
    /*
     * Expected format:
     * {
     *   "threats": [
     *     {
     *       "name": "Emotet Malware",
     *       "severity": "P1 - Critical",
     *       "category": "Malware",
     *       "source": "Feed-Name",
     *       "iocs": [
     *         {"type": "IP Address", "value": "192.168.1.1"},
     *         {"type": "Domain",     "value": "evil.com"}
     *       ]
     *     }
     *   ]
     * }
     */
    private static ParseResult parseCustomJson(Threat_Feed__c feed, String body) {
        ParseResult result = new ParseResult();
        try {
            Map<String, Object> root = (Map<String, Object>) JSON.deserializeUntyped(body);
            List<Object> threatObjs  = (List<Object>) root.get('threats');
            if (threatObjs == null) {
                result.errors.add('No "threats" array in Custom JSON payload');
                return result;
            }

            for (Object obj : threatObjs) {
                Map<String, Object> t = (Map<String, Object>) obj;

                String tName = (String) t.get('name');
                String tSev  = (String) t.get('severity');
                if (String.isBlank(tName) || String.isBlank(tSev)) {
                    result.errors.add('Skipped threat with missing name or severity');
                    continue;
                }
                Threat__c threat = new Threat__c(
                    Name             = tName,
                    Severity__c      = tSev,
                    Category__c      = (String)  t.get('category'),
                    Source__c        = (String)  t.get('source'),
                    Status__c        = 'New',
                    Is_Active__c     = true,
                    Detected_Date__c = System.now()
                );
                Integer threatIdx = result.threats.size();
                result.threats.add(threat);

                // Collect IOC stubs keyed by threat index so each IOC links to the correct threat
                List<Object> iocObjs = (List<Object>) t.get('iocs');
                if (iocObjs != null) {
                    List<Indicator_of_Compromise__c> iocList = new List<Indicator_of_Compromise__c>();
                    for (Object iObj : iocObjs) {
                        Map<String, Object> i = (Map<String, Object>) iObj;
                        String iocType  = (String) i.get('type');
                        String iocValue = (String) i.get('value');
                        if (String.isBlank(iocType) || String.isBlank(iocValue)) {
                            result.errors.add('Skipped IOC with missing type or value');
                            continue;
                        }
                        Indicator_of_Compromise__c ioc = new Indicator_of_Compromise__c(
                            IOC_Type__c   = iocType,
                            Value__c      = iocValue,
                            Is_Active__c  = true,
                            First_Seen__c = System.now(),
                            Last_Seen__c  = System.now()
                        );
                        iocList.add(ioc);
                        result.iocs.add(ioc);
                    }
                    result.threatIOCMap.put(threatIdx, iocList);
                }
            }
        } catch (Exception e) {
            result.errors.add('Custom JSON parse error: ' + e.getMessage());
        }
        return result;
    }

    // ─── OTX (AlienVault) Parser ────────────────────────────────────────────────
    /*
     * Minimal OTX pulse format:
     * { "results": [ { "name": "...", "description": "...",
     *   "indicators": [{"type":"...", "indicator":"..."}] } ] }
     */
    private static ParseResult parseOTX(Threat_Feed__c feed, String body) {
        ParseResult result = new ParseResult();
        try {
            Map<String, Object> root = (Map<String, Object>) JSON.deserializeUntyped(body);
            List<Object> pulses      = (List<Object>) root.get('results');
            if (pulses == null) {
                result.errors.add('No "results" array in OTX payload');
                return result;
            }

            for (Object pObj : pulses) {
                Map<String, Object> pulse = (Map<String, Object>) pObj;

                String pulseName = (String) pulse.get('name');
                String pulseDesc = (String) pulse.get('description');

                if (String.isBlank(pulseName)) {
                    result.errors.add('Skipped OTX pulse with missing name');
                    continue;
                }

                Threat__c threat = new Threat__c(
                    Name             = pulseName,
                    Description__c   = pulseDesc,
                    Source__c        = 'OTX',
                    Category__c      = inferOTXCategory(pulseName, pulseDesc),
                    Severity__c      = inferOTXSeverity(pulseName, pulseDesc),
                    Status__c        = 'New',
                    Is_Active__c     = true,
                    Detected_Date__c = System.now()
                );
                Integer threatIdx = result.threats.size();
                result.threats.add(threat);

                List<Object> indicators = (List<Object>) pulse.get('indicators');
                if (indicators != null) {
                    List<Indicator_of_Compromise__c> iocList = new List<Indicator_of_Compromise__c>();
                    for (Object iObj : indicators) {
                        Map<String, Object> ind = (Map<String, Object>) iObj;
                        String rawType          = (String) ind.get('type');
                        String mappedType       = mapOTXType(rawType);
                        if (mappedType == null) continue;

                        String iocValue = (String) ind.get('indicator');
                        if (String.isBlank(iocValue)) {
                            result.errors.add('Skipped OTX indicator with missing value');
                            continue;
                        }

                        Indicator_of_Compromise__c ioc = new Indicator_of_Compromise__c(
                            IOC_Type__c   = mappedType,
                            Value__c      = iocValue,
                            Is_Active__c  = true,
                            First_Seen__c = System.now(),
                            Last_Seen__c  = System.now()
                        );
                        iocList.add(ioc);
                        result.iocs.add(ioc);
                    }
                    result.threatIOCMap.put(threatIdx, iocList);
                }
            }
        } catch (Exception e) {
            result.errors.add('OTX parse error: ' + e.getMessage());
        }
        return result;
    }

    // ─── OTX Inference Helpers ────────────────────────────────────────────────
    private static String inferOTXSeverity(String name, String description) {
        String combined = ((name == null ? '' : name) + ' ' + (description == null ? '' : description)).toLowerCase();
        if (combined.contains('critical') || combined.contains('apt') || combined.contains('nation-state')) {
            return 'P1 - Critical';
        } else if (combined.contains('high') || combined.contains('ransomware') || combined.contains('exploit')) {
            return 'P2 - High';
        } else if (combined.contains('low') || combined.contains('informational')) {
            return 'P4 - Low';
        }
        return 'P3 - Medium';
    }

    // Bug 1 fix: all return values must be valid Category__c picklist entries
    private static String inferOTXCategory(String name, String description) {
        String combined = ((name == null ? '' : name) + ' ' + (description == null ? '' : description)).toLowerCase();
        if (combined.contains('ransomware'))                               return 'Ransomware';
        if (combined.contains('phish'))                                    return 'Phishing';
        if (combined.contains('ddos'))                                     return 'DDoS';
        if (combined.contains('zero day') || combined.contains('0day'))    return 'Zero Day';
        if (combined.contains('supply chain'))                             return 'Supply Chain';
        if (combined.contains('insider'))                                  return 'Insider Threat';
        if (combined.contains('social engineering'))                       return 'Social Engineering';
        // 'APT', 'C2', 'Botnet' are not valid picklist values — map to closest valid option
        return 'Malware';
    }

    private static String mapOTXType(String otxType) {
        if (otxType == null) return null;
        Map<String, String> typeMap = new Map<String, String>{
            'IPv4'     => 'IP Address',
            'IPv6'     => 'IP Address',
            'domain'   => 'Domain',
            'URL'      => 'URL',
            'hostname' => 'Domain',
            'email'    => 'Email',
            'FileHash-MD5'    => 'File Hash MD5',
            'FileHash-SHA1'   => 'File Hash SHA1',
            'FileHash-SHA256' => 'File Hash SHA256'
        };
        return typeMap.get(otxType);
    }
}
