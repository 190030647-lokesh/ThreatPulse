List<Threat__c> threats = [SELECT Id, Name, Severity__c, Status__c, Is_Active__c FROM Threat__c LIMIT 10];
System.debug('=== Threat count: ' + threats.size() + ' ===');
for(Threat__c t : threats) System.debug(t.Name + ' | ' + t.Severity__c + ' | ' + t.Status__c + ' | Active=' + t.Is_Active__c);

List<Incident__c> incs = [SELECT Id, Status__c, Severity__c FROM Incident__c LIMIT 10];
System.debug('=== Incident count: ' + incs.size() + ' ===');

List<Indicator_of_Compromise__c> iocs = [SELECT Id, IOC_Type__c, Value__c FROM Indicator_of_Compromise__c LIMIT 10];
System.debug('=== IOC count: ' + iocs.size() + ' ===');
