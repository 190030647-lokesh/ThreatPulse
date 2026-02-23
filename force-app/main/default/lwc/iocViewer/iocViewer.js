import { LightningElement, wire, track } from 'lwc';
import { refreshApex } from '@salesforce/apex';
import { ShowToastEvent } from 'lightning/platformShowToastEvent';
import { subscribe, unsubscribe, onError } from 'lightning/empApi';
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

const IOC_CHANNEL = '/event/ThreatPulse_Event__e';

export default class IocViewer extends LightningElement {
    // @track needed so the iocs getter re-evaluates when typeFilter changes
    @track typeFilter   = '';
    @track errorMsg;

    // Reactive @wire parameters â€” plain primitives, wire re-fires on assignment
    searchTerm   = '';
    activeFilter = 'true';
    selectedRows = [];

    typeOptions   = TYPE_OPTIONS;
    activeOptions = ACTIVE_OPTIONS;
    columns       = COLUMNS;

    // Stores the full wire provisioned object so we can call refreshApex
    _wiredResult;
    _cachedData;     // retains last successful result so UI shows stale data instead of spinner during refresh
    _subscription;

    // â”€â”€â”€ @wire â€” reactive, cacheable, auto-refreshes via refreshApex â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    // Bug 7 fix: typeFilter is now a reactive wire param — wire re-fires on type change (server-side)
    @wire(searchIOCs, { searchTerm: '$searchTerm', activeFilter: '$activeFilter', typeFilter: '$typeFilter' })
    wiredIOCs(result) {
        this._wiredResult = result;
        if (result.data) {
            this._cachedData = result.data;  // cache for stale-while-revalidate pattern
            this.errorMsg    = undefined;
        } else if (result.error) {
            this.errorMsg = this._errMsg(result.error);
        }
    }

    // â”€â”€â”€ Lifecycle â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    connectedCallback() {
        // Register a global error handler for empApi
        onError(error => {
            console.error('[IocViewer] EmpApi error:', JSON.stringify(error));
        });
        // Subscribe to ThreatPulse Platform Events
        subscribe(IOC_CHANNEL, -1, (message) => {
            const evtType = message.data && message.data.payload && message.data.payload.Event_Type__c;
            if (evtType && evtType.startsWith('IOC_')) {
                // Another user/action deactivated IOCs â€” refresh from server
                refreshApex(this._wiredResult);
            }
        }).then(sub => {
            this._subscription = sub;
        });
    }

    disconnectedCallback() {
        if (this._subscription) {
            unsubscribe(this._subscription, () => {});
            this._subscription = undefined;
        }
    }

    // â”€â”€â”€ Computed â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    // Bug 7 fix: typeFilter is now server-side via wire — no client filtering needed
    // Bug 4 fix: fall back to _cachedData during refreshApex so no spinner flash on background refresh
    get iocs() {
        return (this._wiredResult && this._wiredResult.data) || this._cachedData || [];
    }

    get isLoading() {
        // Bug 4 fix: only spin on initial load; show stale data during background refreshes
        return !this._wiredResult ||
               (!this._wiredResult.data && !this._wiredResult.error && !this._cachedData);
    }

    get noResults() {
        return !this.isLoading && this.iocs.length === 0;
    }

    get hasSelected() {
        return this.selectedRows.length > 0;
    }

    get recordCountLabel() {
        return `${this.iocs.length} IOC${this.iocs.length !== 1 ? 's' : ''} found`;
    }

    // â”€â”€â”€ Filter Handlers (reactive props drive wire automatically) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    handleSearchInput(event) { this.searchTerm  = event.detail.value; }
    handleTypeFilter(event)  { this.typeFilter   = event.detail.value; }
    handleActiveFilter(event){ this.activeFilter = event.detail.value; }

    handleClear() {
        this.searchTerm   = '';
        this.typeFilter   = '';
        this.activeFilter = 'true';
        this.selectedRows = [];
        this.errorMsg     = undefined;
        // Force re-fetch in case values didn't change (wire won't re-fire otherwise)
        refreshApex(this._wiredResult);
    }

    // Bug 1 fix: onsearch fires when user clicks X (event.detail.value = '') — must update searchTerm
    // onclick from Search button has no useful detail — only refreshes manually
    handleSearch(event) {
        if (event && event.detail && event.detail.value !== undefined) {
            this.searchTerm = event.detail.value;  // X-clear sets this to ''
        }
        refreshApex(this._wiredResult);
    }

    // â”€â”€â”€ Selection & Actions â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    handleRowSelection(event) {
        this.selectedRows = event.detail.selectedRows.map(r => r.Id);
    }

    async handleRowAction(event) {
        const { name } = event.detail.action;
        const row      = event.detail.row;
        if (name === 'deactivate') {
            try {
                await deactivateIOC({ iocId: row.Id });
                this._toast('Deactivated', `IOC "${row.Value__c}" deactivated.`, 'warning');
                // Invalidate wire cache so updated Is_Active__c is reflected
                await refreshApex(this._wiredResult);
            } catch (e) {
                this.errorMsg = this._errMsg(e);
            }
        }
    }

    async handleBulkDeactivate() {
        if (!this.selectedRows.length) return;
        try {
            await deactivateIOCList({ iocIds: this.selectedRows });
            const count = this.selectedRows.length;
            this.selectedRows = [];
            this._toast('Deactivated', `${count} IOC(s) deactivated.`, 'warning');
            await refreshApex(this._wiredResult);
        } catch (e) {
            this.errorMsg = this._errMsg(e);
        }
    }

    // â”€â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    _toast(title, message, variant) {
        this.dispatchEvent(new ShowToastEvent({ title, message, variant }));
    }

    _errMsg(err) {
        if (Array.isArray(err.body)) return err.body.map(e => e.message).join(', ');
        if (err.body && err.body.message) return err.body.message;
        return err.message || 'Unknown error';
    }
}
