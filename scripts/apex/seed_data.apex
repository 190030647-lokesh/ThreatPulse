// ThreatPulse — Seed Sample Data
// Run: sf apex run --target-org ThreatPulse-Scratch --file scripts/apex/seed_data.apex

// ─── Threats ────────────────────────────────────────────────────────────────
List<Threat__c> threats = new List<Threat__c>{
    new Threat__c(
        Name             = 'APT29 Spear Phishing Campaign',
        Severity__c      = 'P1 - Critical',
        Status__c        = 'New',
        Category__c      = 'Phishing',
        Source__c        = 'OTX',
        Description__c   = 'Highly targeted spear phishing emails impersonating government agencies to steal credentials.',
        Is_Active__c     = true,
        Confidence_Score__c = 92,
        Detected_Date__c = System.now().addDays(-2)
    ),
    new Threat__c(
        Name             = 'Emotet Malware Dropper',
        Severity__c      = 'P2 - High',
        Status__c        = 'In Progress',
        Category__c      = 'Malware',
        Source__c        = 'VirusTotal',
        Description__c   = 'Emotet banking trojan variant spreading via malicious Office documents in email attachments.',
        Is_Active__c     = true,
        Confidence_Score__c = 87,
        Detected_Date__c = System.now().addDays(-5)
    ),
    new Threat__c(
        Name             = 'LockBit 3.0 Ransomware',
        Severity__c      = 'P1 - Critical',
        Status__c        = 'New',
        Category__c      = 'Ransomware',
        Source__c        = 'MITRE ATT&CK',
        Description__c   = 'LockBit 3.0 ransomware targeting enterprise file servers via RDP brute force.',
        Is_Active__c     = true,
        Confidence_Score__c = 95,
        Detected_Date__c = System.now().addDays(-1)
    ),
    new Threat__c(
        Name             = 'SQL Injection on Customer Portal',
        Severity__c      = 'P2 - High',
        Status__c        = 'In Progress',
        Category__c      = 'Web Attack',
        Source__c        = 'Internal SIEM',
        Description__c   = 'Blind SQL injection attempts detected on login endpoint. Attacker enumerating database structure.',
        Is_Active__c     = true,
        Confidence_Score__c = 78,
        Detected_Date__c = System.now().addDays(-3)
    ),
    new Threat__c(
        Name             = 'Cobalt Strike Beacon Detected',
        Severity__c      = 'P3 - Medium',
        Status__c        = 'New',
        Category__c      = 'C2',
        Source__c        = 'Internal EDR',
        Description__c   = 'Cobalt Strike beacon traffic identified on internal workstation communicating with known C2 server.',
        Is_Active__c     = true,
        Confidence_Score__c = 83,
        Detected_Date__c = System.now().addDays(-4)
    ),
    new Threat__c(
        Name             = 'Old Log4Shell Exploit Attempt',
        Severity__c      = 'P4 - Low',
        Status__c        = 'Closed',
        Category__c      = 'Exploit',
        Source__c        = 'WAF Logs',
        Description__c   = 'Log4Shell (CVE-2021-44228) exploit attempt blocked by WAF. Patched systems not vulnerable.',
        Is_Active__c     = false,
        Confidence_Score__c = 60,
        Detected_Date__c = System.now().addDays(-30)
    )
};
insert threats;
System.debug('Inserted ' + threats.size() + ' threats.');

// ─── IOCs ────────────────────────────────────────────────────────────────────
List<Indicator_of_Compromise__c> iocs = new List<Indicator_of_Compromise__c>{
    new Indicator_of_Compromise__c(
        Name         = 'APT29-C2-IP',
        Threat__c    = threats[0].Id,
        IOC_Type__c  = 'IP Address',
        Value__c     = '185.220.101.47',
        Is_Active__c = true,
        Confidence__c = 90,
        First_Seen__c = System.now().addDays(-2),
        Last_Seen__c  = System.now()
    ),
    new Indicator_of_Compromise__c(
        Name         = 'APT29-Phishing-Domain',
        Threat__c    = threats[0].Id,
        IOC_Type__c  = 'Domain',
        Value__c     = 'secure-gov-login.malicious.net',
        Is_Active__c = true,
        Confidence__c = 95,
        First_Seen__c = System.now().addDays(-2),
        Last_Seen__c  = System.now()
    ),
    new Indicator_of_Compromise__c(
        Name         = 'Emotet-Hash',
        Threat__c    = threats[1].Id,
        IOC_Type__c  = 'File Hash',
        Value__c     = 'a3f5bc12d8e4a1c7b9f2e6d0c4b8a2f1',
        Is_Active__c = true,
        Confidence__c = 87,
        First_Seen__c = System.now().addDays(-5),
        Last_Seen__c  = System.now().addDays(-1)
    ),
    new Indicator_of_Compromise__c(
        Name         = 'LockBit-C2-IP',
        Threat__c    = threats[2].Id,
        IOC_Type__c  = 'IP Address',
        Value__c     = '91.214.124.20',
        Is_Active__c = true,
        Confidence__c = 95,
        First_Seen__c = System.now().addDays(-1),
        Last_Seen__c  = System.now()
    ),
    new Indicator_of_Compromise__c(
        Name         = 'SQLi-Attacker-IP',
        Threat__c    = threats[3].Id,
        IOC_Type__c  = 'IP Address',
        Value__c     = '203.0.113.99',
        Is_Active__c = true,
        Confidence__c = 78,
        First_Seen__c = System.now().addDays(-3),
        Last_Seen__c  = System.now()
    ),
    new Indicator_of_Compromise__c(
        Name         = 'CobaltStrike-C2-Domain',
        Threat__c    = threats[4].Id,
        IOC_Type__c  = 'Domain',
        Value__c     = 'updates.windowsupdate-cdn.com',
        Is_Active__c = true,
        Confidence__c = 83,
        First_Seen__c = System.now().addDays(-4),
        Last_Seen__c  = System.now()
    )
};
insert iocs;
System.debug('Inserted ' + iocs.size() + ' IOCs.');

// ─── Incidents ───────────────────────────────────────────────────────────────
List<Incident__c> incidents = new List<Incident__c>{
    new Incident__c(
        Threat__c        = threats[0].Id,
        Severity__c      = 'P1 - Critical',
        Status__c        = 'Open',
        Detected_Date__c = System.now().addDays(-2)
    ),
    new Incident__c(
        Threat__c        = threats[1].Id,
        Severity__c      = 'P2 - High',
        Status__c        = 'In Progress',
        Detected_Date__c = System.now().addDays(-5)
    ),
    new Incident__c(
        Threat__c        = threats[2].Id,
        Severity__c      = 'P1 - Critical',
        Status__c        = 'Open',
        Detected_Date__c = System.now().addDays(-1)
    )
};
insert incidents;
System.debug('Inserted ' + incidents.size() + ' incidents.');

// ─── Threat Feeds ────────────────────────────────────────────────────────────
List<Threat_Feed__c> feeds = new List<Threat_Feed__c>{
    new Threat_Feed__c(
        Name                   = 'AlienVault OTX',
        Feed_Type__c           = 'OTX',
        Feed_URL__c            = 'https://otx.alienvault.com/api/v1/pulses/subscribed',
        Is_Active__c           = true,
        Status__c              = 'Active',
        Sync_Frequency_Hours__c = 6
    ),
    new Threat_Feed__c(
        Name                   = 'VirusTotal Intelligence',
        Feed_Type__c           = 'Custom JSON',
        Feed_URL__c            = 'https://www.virustotal.com/api/v3/feeds/files',
        Is_Active__c           = true,
        Status__c              = 'Active',
        Sync_Frequency_Hours__c = 12
    ),
    new Threat_Feed__c(
        Name                   = 'MITRE ATT&CK STIX Feed',
        Feed_Type__c           = 'STIX/TAXII',
        Feed_URL__c            = 'https://cti-taxii.mitre.org/stix/collections',
        Is_Active__c           = true,
        Status__c              = 'Active',
        Sync_Frequency_Hours__c = 24
    )
};
insert feeds;
System.debug('Inserted ' + feeds.size() + ' threat feeds.');

System.debug('=== ThreatPulse seed data complete! ===');
System.debug('Threats: ' + threats.size());
System.debug('IOCs: ' + iocs.size());
System.debug('Incidents: ' + incidents.size());
System.debug('Feeds: ' + feeds.size());
