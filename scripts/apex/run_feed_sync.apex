// ThreatPulse — Run Threat Feed Sync Batch
// Executes ThreatFeedSyncBatch to pull data from all active threat feeds.
// Run via CLI:  sf apex run --target-org ThreatPulse-Scratch --file scripts/apex/hello.apex

Id jobId = Database.executeBatch(new ThreatFeedSyncBatch(), 10);
System.debug('ThreatFeedSyncBatch enqueued. Job ID: ' + jobId);
