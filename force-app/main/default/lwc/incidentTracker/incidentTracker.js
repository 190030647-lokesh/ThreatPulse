import { LightningElement, wire, track } from 'lwc';
import { refreshApex } from '@salesforce/apex';
import { ShowToastEvent } from 'lightning/platformShowToastEvent';
import getIncidents from '@salesforce/apex/IncidentController.getIncidents';
import assignToMe from '@salesforce/apex/IncidentController.assignToMe';
import resolveIncident from '@salesforce/apex/IncidentController.resolveIncident';
import closeIncident from '@salesforce/apex/IncidentController.closeIncident';

const COLUMNS = [
    { label: 'Incident #',  fieldName: 'Name',             type: 'text'                                 },
    { label: 'Severity',    fieldName: 'Severity__c',      type: 'text'                                 },
    { label: 'Status',      fieldName: 'Status__c',        type: 'text'                                 },
    { label: 'Detected',    fieldName: 'Detected_Date__c', type: 'date',
      typeAttributes: { year: 'numeric', month: 'short', day: '2-digit' }                               },
    { label: 'Resolved',    fieldName: 'Resolved_Date__c', type: 'date',
      typeAttributes: { year: 'numeric', month: 'short', day: '2-digit' }                               },
    {
        type: 'action',
        typeAttributes: {
            rowActions: [
                { label: 'Assign to Me', name: 'assign'  },
                { label: 'Resolve',      name: 'resolve' },
                { label: 'Close',        name: 'close'   }
            ]
        }
    }
];

export default class IncidentTracker extends LightningElement {
    @track allIncidents          = [];
    @track showResolveModal      = false;
    @track selectedIncidentId;
    @track selectedIncidentName  = '';
    @track resolutionNotes       = '';
    @track errorMsg;
    @track activeTab             = 'All';
    columns   = COLUMNS;
    _wiredResult;

    @wire(getIncidents)
    wiredIncidents(result) {
        this._wiredResult = result;
        if (result.data) {
            this.allIncidents = result.data;
            this.errorMsg     = undefined;
        } else if (result.error) {
            this.errorMsg = this._errMsg(result.error);
        }
    }

    // ─── Computed ───────────────────────────────────────────────────────────────

    get filteredIncidents() {
        if (this.activeTab === 'All') return this.allIncidents;
        return this.allIncidents.filter(i => i.Status__c === this.activeTab);
    }

    get recordCountLabel() {
        const count = this.filteredIncidents.length;
        return `${count} incident${count !== 1 ? 's' : ''}`;
    }

    // ─── Tab ────────────────────────────────────────────────────────────────────

    handleTabChange(event) {
        this.activeTab = event.detail.value;
    }

    // ─── Row Actions ─────────────────────────────────────────────────────────────

    async handleRowAction(event) {
        const { name } = event.detail.action;
        const row      = event.detail.row;

        if (name === 'assign') {
            try {
                await assignToMe({ incidentId: row.Id });
                await refreshApex(this._wiredResult);
                this._toast('Assigned', `${row.Name} assigned to you.`, 'success');
            } catch (e) {
                this.errorMsg = this._errMsg(e);
            }
        } else if (name === 'resolve') {
            this.selectedIncidentId   = row.Id;
            this.selectedIncidentName = row.Name;
            this.resolutionNotes      = '';
            this.showResolveModal     = true;
        } else if (name === 'close') {
            try {
                await closeIncident({ incidentId: row.Id });
                await refreshApex(this._wiredResult);
                this._toast('Closed', `${row.Name} has been closed.`, 'warning');
            } catch (e) {
                this.errorMsg = this._errMsg(e);
            }
        }
    }

    // ─── Resolve Modal ────────────────────────────────────────────────────────────

    handleNotesChange(event) {
        this.resolutionNotes = event.detail.value;
    }

    handleCloseModal() {
        this.showResolveModal = false;
    }

    async handleConfirmResolve() {
        if (!this.resolutionNotes || !this.resolutionNotes.trim()) {
            this.errorMsg = 'Resolution notes are required.';
            return;
        }
        try {
            await resolveIncident({
                incidentId: this.selectedIncidentId,
                notes: this.resolutionNotes
            });
            this.showResolveModal = false;
            this.errorMsg         = undefined;
            await refreshApex(this._wiredResult);
            this._toast('Resolved', `${this.selectedIncidentName} marked as resolved.`, 'success');
        } catch (e) {
            this.errorMsg = this._errMsg(e);
        }
    }

    // ─── Helpers ────────────────────────────────────────────────────────────────

    _toast(title, message, variant) {
        this.dispatchEvent(new ShowToastEvent({ title, message, variant }));
    }

    _errMsg(err) {
        if (Array.isArray(err.body)) return err.body.map(e => e.message).join(', ');
        if (err.body && err.body.message) return err.body.message;
        return err.message || 'Unknown error';
    }
}
