import { LightningElement, wire, track } from 'lwc';
import { refreshApex } from '@salesforce/apex';
import { ShowToastEvent } from 'lightning/platformShowToastEvent';
import getMetrics from '@salesforce/apex/DashboardMetricsController.getMetrics';
import getRecentThreats from '@salesforce/apex/DashboardMetricsController.getRecentThreats';
import getRecentIncidents from '@salesforce/apex/DashboardMetricsController.getRecentIncidents';

const THREAT_COLUMNS = [
    { label: 'Name',          fieldName: 'Name',             type: 'text'    },
    { label: 'Severity',      fieldName: 'Severity__c',      type: 'text'    },
    { label: 'Category',      fieldName: 'Category__c',      type: 'text'    },
    { label: 'Status',        fieldName: 'Status__c',        type: 'text'    },
    { label: 'Source',        fieldName: 'Source__c',        type: 'text'    },
    { label: 'Detected',      fieldName: 'Detected_Date__c', type: 'date',
      typeAttributes: { year: 'numeric', month: 'short', day: '2-digit' } }
];

const INCIDENT_COLUMNS = [
    { label: 'Incident #',    fieldName: 'Name',             type: 'text'    },
    { label: 'Severity',      fieldName: 'Severity__c',      type: 'text'    },
    { label: 'Status',        fieldName: 'Status__c',        type: 'text'    },
    { label: 'Detected',      fieldName: 'Detected_Date__c', type: 'date',
      typeAttributes: { year: 'numeric', month: 'short', day: '2-digit' } },
    { label: 'Resolved',      fieldName: 'Resolved_Date__c', type: 'date',
      typeAttributes: { year: 'numeric', month: 'short', day: '2-digit' } }
];

const POLL_INTERVAL_MS = 60000; // auto-refresh every 60 seconds

export default class ThreatDashboard extends LightningElement {
    @track metrics;
    @track recentThreats = [];
    @track recentIncidents = [];
    @track error;
    @track isLoading = true;

    threatColumns    = THREAT_COLUMNS;
    incidentColumns  = INCIDENT_COLUMNS;

    _metricsWired;
    _threatsWired;
    _incidentsWired;
    _pollTimer;
    _isRefreshing = false;

    @wire(getMetrics)
    wiredMetrics(result) {
        this._metricsWired = result;
        if (result.data) {
            this.error     = undefined;
            this.metrics   = this._enrichMetrics(result.data);
            this.isLoading = false;
        } else if (result.error) {
            this.error     = this._errorMsg(result.error);
            this.metrics   = undefined;
            this.isLoading = false;
        }
    }

    @wire(getRecentThreats, { limitCount: 10 })
    wiredThreats(result) {
        this._threatsWired = result;
        if (result.data) {
            this.recentThreats = result.data;
        } else if (result.error) {
            this.error = this._errorMsg(result.error);
        }
    }

    @wire(getRecentIncidents, { limitCount: 10 })
    wiredIncidents(result) {
        this._incidentsWired = result;
        if (result.data) {
            this.recentIncidents = result.data;
        } else if (result.error) {
            this.error = this._errorMsg(result.error);
        }
    }

    // ─── Lifecycle ───────────────────────────────────────────────────────────────

    connectedCallback() {
        this._pollTimer = setInterval(() => { this._doRefresh(true); }, POLL_INTERVAL_MS);
    }

    disconnectedCallback() {
        if (this._pollTimer) {
            clearInterval(this._pollTimer);
            this._pollTimer = undefined;
        }
    }

    // ─── Computed ───────────────────────────────────────────────────────────────

    get hasSeverityData() {
        return this.metrics && this.metrics.bySeverity && this.metrics.bySeverity.length > 0;
    }

    get hasCategoryData() {
        return this.metrics && this.metrics.byCategory && this.metrics.byCategory.length > 0;
    }

    // Inverse getters for lwc:if (templates don't support ! negation)
    get noSeverityData() { return !this.hasSeverityData; }
    get noCategoryData() { return !this.hasCategoryData; }
    get showSpinner()    { return this.isLoading; }

    // ─── Enrich metrics with bar chart widths ────────────────────────────────────

    _enrichMetrics(raw) {
        const enriched = { ...raw };

        const sevMax = raw.bySeverity && raw.bySeverity.length
            ? Math.max(...raw.bySeverity.map(r => r.count)) : 1;

        enriched.bySeverity = (raw.bySeverity || []).map(r => ({
            ...r,
            barStyle: `width:${Math.round((r.count / sevMax) * 100)}%`
        }));

        const catMax = raw.byCategory && raw.byCategory.length
            ? Math.max(...raw.byCategory.map(r => r.count)) : 1;

        enriched.byCategory = (raw.byCategory || []).map(r => ({
            ...r,
            barStyle: `width:${Math.round((r.count / catMax) * 100)}%`
        }));

        return enriched;
    }

    // ─── Handlers ───────────────────────────────────────────────────────────────

    handleRefresh() {
        this._doRefresh(false);
    }

    async _doRefresh(silent) {
        if (this._isRefreshing) return; // prevent concurrent refreshes
        this._isRefreshing = true;
        this.isLoading = true;
        try {
            await Promise.all([
                refreshApex(this._metricsWired),
                refreshApex(this._threatsWired),
                refreshApex(this._incidentsWired)
            ]);
        } finally {
            this.isLoading = false;
            this._isRefreshing = false;
        }
        if (!silent) {
            this.dispatchEvent(new ShowToastEvent({
                title: 'Dashboard', message: 'Data refreshed.', variant: 'success', mode: 'dismissable'
            }));
        }
    }

    _errorMsg(err) {
        if (Array.isArray(err.body)) return err.body.map(e => e.message).join(', ');
        if (err.body && err.body.message) return err.body.message;
        return err.message || 'Unknown error';
    }
}
