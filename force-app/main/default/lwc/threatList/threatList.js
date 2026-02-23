import { LightningElement, wire, track } from 'lwc';
import { refreshApex } from '@salesforce/apex';
import { ShowToastEvent } from 'lightning/platformShowToastEvent';
import getThreats from '@salesforce/apex/ThreatController.getThreats';
import createThreat from '@salesforce/apex/ThreatController.createThreat';
import updateThreatStatus from '@salesforce/apex/ThreatController.updateThreatStatus';
import deleteThreat from '@salesforce/apex/ThreatController.deleteThreat';

const SEVERITY_OPTIONS = [
    { label: 'P1 - Critical', value: 'P1 - Critical' },
    { label: 'P2 - High',     value: 'P2 - High'     },
    { label: 'P3 - Medium',   value: 'P3 - Medium'   },
    { label: 'P4 - Low',      value: 'P4 - Low'      }
];

const STATUS_OPTIONS = [
    { label: 'New',         value: 'New'         },
    { label: 'In Progress', value: 'In Progress' },
    { label: 'Contained',   value: 'Contained'   },
    { label: 'Resolved',    value: 'Resolved'    },
    { label: 'Closed',      value: 'Closed'      }
];

const CATEGORY_OPTIONS = [
    { label: 'Malware',          value: 'Malware'          },
    { label: 'Phishing',         value: 'Phishing'         },
    { label: 'Ransomware',       value: 'Ransomware'       },
    { label: 'Insider Threat',   value: 'Insider Threat'   },
    { label: 'DDoS',             value: 'DDoS'             },
    { label: 'Zero Day',         value: 'Zero Day'         },
    { label: 'Supply Chain',     value: 'Supply Chain'     },
    { label: 'Social Engineering', value: 'Social Engineering' },
    { label: 'Other',            value: 'Other'            }
];

const COLUMNS = [
    { label: 'Name',          fieldName: 'Name',             type: 'text'                               },
    { label: 'Severity',      fieldName: 'Severity__c',      type: 'text'                               },
    { label: 'Category',      fieldName: 'Category__c',      type: 'text'                               },
    { label: 'Status',        fieldName: 'Status__c',        type: 'text'                               },
    { label: 'Source',        fieldName: 'Source__c',        type: 'text'                               },
    { label: 'Detected',      fieldName: 'Detected_Date__c', type: 'date',
      typeAttributes: { year: 'numeric', month: 'short', day: '2-digit' }                               },
    { label: 'Active',        fieldName: 'Is_Active__c',     type: 'boolean'                            },
    {
        type: 'action',
        typeAttributes: {
            rowActions: [
                { label: 'Mark In Progress', name: 'in_progress' },
                { label: 'Mark Contained',   name: 'contained'   },
                { label: 'Close Threat',     name: 'close'       },
                { label: 'Delete',           name: 'delete'      }
            ]
        }
    }
];

export default class ThreatList extends LightningElement {
    @track allThreats    = [];
    @track errorMsg;
    @track showModal     = false;
    @track modalData     = {};

    @track severityFilter  = '';
    @track statusFilter    = '';
    @track categoryFilter  = '';
    @track searchTerm      = '';
    rowOffset              = 0;

    severityOptions  = SEVERITY_OPTIONS;
    statusOptions    = STATUS_OPTIONS;
    categoryOptions  = CATEGORY_OPTIONS;
    columns          = COLUMNS;

    _wiredResult;

    get modalTitle() { return 'New Threat'; }

    @wire(getThreats)
    wiredThreats(result) {
        this._wiredResult = result;
        if (result.data) {
            this.allThreats = result.data;
            this.errorMsg   = undefined;
        } else if (result.error) {
            this.errorMsg   = this._errMsg(result.error);
        }
    }

    // ─── Filters ─────────────────────────────────────────────────────────────────

    get filteredThreats() {
        return this.allThreats.filter(t => {
            const matchSev  = !this.severityFilter || t.Severity__c === this.severityFilter;
            const matchStat = !this.statusFilter   || t.Status__c   === this.statusFilter;
            const matchCat  = !this.categoryFilter || t.Category__c === this.categoryFilter;
            const matchSrch = !this.searchTerm     ||
                (t.Name && t.Name.toLowerCase().includes(this.searchTerm.toLowerCase()));
            return matchSev && matchStat && matchCat && matchSrch;
        });
    }

    get recordCountLabel() {
        const count = this.filteredThreats.length;
        return `${count} record${count !== 1 ? 's' : ''}`;
    }

    handleSearch(event)         { this.searchTerm     = event.detail.value;        }
    handleSeverityFilter(event) { this.severityFilter  = event.detail.value;       }
    handleStatusFilter(event)   { this.statusFilter    = event.detail.value;       }
    handleCategoryFilter(event) { this.categoryFilter  = event.detail.value;       }
    handleClearFilters()        {
        this.severityFilter = '';
        this.statusFilter   = '';
        this.categoryFilter = '';
        this.searchTerm     = '';
    }

    // ─── Modal ────────────────────────────────────────────────────────────────────

    handleNewThreat() {
        this.modalData  = { severity: 'P3 - Medium', category: 'Malware' };
        this.showModal  = true;
    }

    handleCloseModal() { this.showModal = false; }

    handleModalFieldChange(event) {
        const field = event.target.dataset.field;
        this.modalData = { ...this.modalData, [field]: event.detail.value };
    }

    async handleSaveThreat() {
        const { name, severity, category, source, description } = this.modalData;
        if (!name || !severity) {
            this.errorMsg = 'Name and Severity are required.';
            return;
        }
        try {
            await createThreat({ name, severity, category, source, description });
            this.showModal = false;
            this.modalData = {};
            this.errorMsg  = undefined;
            await refreshApex(this._wiredResult);
            this._toast('Threat created', `"${name}" has been added.`, 'success');
        } catch (e) {
            this.errorMsg = this._errMsg(e);
        }
    }

    // ─── Row Actions ──────────────────────────────────────────────────────────────

    async handleRowAction(event) {
        const { name } = event.detail.action;
        const row      = event.detail.row;

        const statusMap = { in_progress: 'In Progress', contained: 'Contained', close: 'Closed' };

        if (statusMap[name]) {
            try {
                await updateThreatStatus({ threatId: row.Id, newStatus: statusMap[name] });
                await refreshApex(this._wiredResult);
                this._toast('Updated', `Threat status set to ${statusMap[name]}`, 'success');
            } catch (e) {
                this.errorMsg = this._errMsg(e);
            }
        } else if (name === 'delete') {
            try {
                await deleteThreat({ threatId: row.Id });
                await refreshApex(this._wiredResult);
                this._toast('Deleted', `Threat "${row.Name}" deleted.`, 'warning');
            } catch (e) {
                this.errorMsg = this._errMsg(e);
            }
        }
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────────

    _toast(title, message, variant) {
        this.dispatchEvent(new ShowToastEvent({ title, message, variant }));
    }

    _errMsg(err) {
        if (Array.isArray(err.body)) return err.body.map(e => e.message).join(', ');
        if (err.body && err.body.message) return err.body.message;
        return err.message || 'Unknown error';
    }
}
