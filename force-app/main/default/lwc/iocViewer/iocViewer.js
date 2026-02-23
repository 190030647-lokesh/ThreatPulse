import { LightningElement, track } from 'lwc';
import { ShowToastEvent } from 'lightning/platformShowToastEvent';
import searchIOCs from '@salesforce/apex/IOCController.searchIOCs';
import deactivateIOC from '@salesforce/apex/IOCController.deactivateIOC';
import deactivateIOCList from '@salesforce/apex/IOCController.deactivateIOCList';

const TYPE_OPTIONS = [
    { label: 'IP Address',       value: 'IP Address'       },
    { label: 'Domain',           value: 'Domain'           },
    { label: 'URL',              value: 'URL'              },
    { label: 'File Hash MD5',    value: 'File Hash MD5'    },
    { label: 'File Hash SHA1',   value: 'File Hash SHA1'   },
    { label: 'File Hash SHA256', value: 'File Hash SHA256' },
    { label: 'Email',            value: 'Email'            },
    { label: 'Registry Key',     value: 'Registry Key'     }
];

const ACTIVE_OPTIONS = [
    { label: 'Active Only',  value: 'true'  },
    { label: 'Show All',     value: 'all'   },
    { label: 'Inactive Only',value: 'false' }
];

const COLUMNS = [
    { label: 'Type',        fieldName: 'IOC_Type__c',  type: 'text'    },
    { label: 'Value',       fieldName: 'Value__c',     type: 'text'    },
    { label: 'Active',      fieldName: 'Is_Active__c', type: 'boolean' },
    { label: 'Confidence',  fieldName: 'Confidence__c', type: 'number',
      typeAttributes: { minimumFractionDigits: 0, maximumFractionDigits: 0 },
      cellAttributes: { suffix: '%' } },
    { label: 'First Seen',  fieldName: 'First_Seen__c',type: 'date',
      typeAttributes: { year: 'numeric', month: 'short', day: '2-digit' } },
    { label: 'Last Seen',   fieldName: 'Last_Seen__c', type: 'date',
      typeAttributes: { year: 'numeric', month: 'short', day: '2-digit' } },
    {
        type: 'action',
        typeAttributes: {
            rowActions: [
                { label: 'Deactivate', name: 'deactivate' }
            ]
        }
    }
];

export default class IocViewer extends LightningElement {
    @track iocs         = [];
    @track isLoading    = false;
    @track errorMsg;

    searchTerm    = '';
    typeFilter    = '';
    activeFilter  = 'true';
    selectedRows  = [];

    typeOptions   = TYPE_OPTIONS;
    activeOptions = ACTIVE_OPTIONS;
    columns       = COLUMNS;

    connectedCallback() {
        this.handleSearch();
    }

    // ─── Computed ───────────────────────────────────────────────────────────────

    get noResults() {
        return !this.isLoading && this.iocs.length === 0;
    }

    get hasSelected() {
        return this.selectedRows.length > 0;
    }

    get recordCountLabel() {
        return `${this.iocs.length} IOC${this.iocs.length !== 1 ? 's' : ''} found`;
    }

    // ─── Handlers ───────────────────────────────────────────────────────────────

    handleSearchInput(event) { this.searchTerm  = event.detail.value; }
    handleTypeFilter(event)  { this.typeFilter   = event.detail.value; }
    handleActiveFilter(event){ this.activeFilter = event.detail.value; }

    handleClear() {
        this.searchTerm   = '';
        this.typeFilter   = '';
        this.activeFilter = 'true';
        this.selectedRows = [];
        this.errorMsg     = undefined;
        this.handleSearch();
    }

    async handleSearch() {
        this.isLoading = true;
        this.errorMsg  = undefined;
        try {
            let results = await searchIOCs({ searchTerm: this.searchTerm, activeFilter: this.activeFilter });

            // Client-side filter by type
            if (this.typeFilter) {
                results = results.filter(r => r.IOC_Type__c === this.typeFilter);
            }
            // Client-side filter by active status
            if (this.activeFilter === 'true') {
                results = results.filter(r => r.Is_Active__c === true);
            } else if (this.activeFilter === 'false') {
                results = results.filter(r => r.Is_Active__c === false);
            }

            this.iocs = results;
        } catch (e) {
            this.errorMsg = this._errMsg(e);
        } finally {
            this.isLoading = false;
        }
    }

    handleRowSelection(event) {
        this.selectedRows = event.detail.selectedRows.map(r => r.Id);
    }

    async handleRowAction(event) {
        const { name } = event.detail.action;
        const row      = event.detail.row;
        if (name === 'deactivate') {
            try {
                await deactivateIOC({ iocId: row.Id });
                this.iocs = this.iocs.map(i =>
                    i.Id === row.Id ? { ...i, Is_Active__c: false } : i
                );
                this._toast('Deactivated', `IOC "${row.Value__c}" deactivated.`, 'warning');
            } catch (e) {
                this.errorMsg = this._errMsg(e);
            }
        }
    }

    async handleBulkDeactivate() {
        if (!this.selectedRows.length) return;
        try {
            await deactivateIOCList({ iocIds: this.selectedRows });
            const deactivatedSet = new Set(this.selectedRows);
            this.iocs = this.iocs.map(i =>
                deactivatedSet.has(i.Id) ? { ...i, Is_Active__c: false } : i
            );
            this._toast('Deactivated', `${this.selectedRows.length} IOC(s) deactivated.`, 'warning');
            this.selectedRows = [];
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
