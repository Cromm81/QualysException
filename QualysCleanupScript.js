/**
 * Qualys Integration - Enhanced Cleanup Script
 * 
 * Use this to clean up RITMs created during testing.
 * Run in Scripts - Background.
 * 
 * WARNING: This will delete RITMs! Use with caution.
 * Always run with DRY_RUN = true first to preview.
 */

var QualysCleanup = Class.create();
QualysCleanup.prototype = {
    
    // ============================================================
    // CONFIGURATION - UPDATE THESE VALUES
    // ============================================================
    
    CATALOG_ITEM_SYS_ID: 'YOUR_CATALOG_ITEM_SYS_ID',  // TODO: Replace
    
    // Safety settings
    DRY_RUN: true,              // Set to false to actually delete
    MAX_DELETE_LIMIT: 500,      // Maximum records to delete (safety)
    
    // ============================================================
    // INITIALIZATION
    // ============================================================
    
    initialize: function() {
        this.deletedRitms = [];
        this.deletedRequests = [];
        this.errors = [];
    },
    
    // ============================================================
    // MAIN CLEANUP METHODS
    // ============================================================
    
    /**
     * Delete all RITMs for the catalog item
     */
    deleteAll: function() {
        gs.info('=== QUALYS CLEANUP: Delete All ===');
        gs.info('Catalog Item: ' + this.CATALOG_ITEM_SYS_ID);
        gs.info('Dry Run: ' + this.DRY_RUN);
        gs.info('');
        
        var gr = new GlideRecord('sc_req_item');
        gr.addQuery('cat_item', this.CATALOG_ITEM_SYS_ID);
        gr.query();
        
        this._processRecords(gr);
    },
    
    /**
     * Delete only RITMs created today
     */
    deleteTodayOnly: function() {
        gs.info('=== QUALYS CLEANUP: Today Only ===');
        gs.info('Catalog Item: ' + this.CATALOG_ITEM_SYS_ID);
        gs.info('Dry Run: ' + this.DRY_RUN);
        gs.info('');
        
        var gr = new GlideRecord('sc_req_item');
        gr.addQuery('cat_item', this.CATALOG_ITEM_SYS_ID);
        gr.addQuery('sys_created_on', '>=', gs.beginningOfToday());
        gr.query();
        
        this._processRecords(gr);
    },
    
    /**
     * Delete RITMs created within a date range
     * @param {string} startDate - Start date (YYYY-MM-DD)
     * @param {string} endDate - End date (YYYY-MM-DD)
     */
    deleteByDateRange: function(startDate, endDate) {
        gs.info('=== QUALYS CLEANUP: Date Range ===');
        gs.info('Catalog Item: ' + this.CATALOG_ITEM_SYS_ID);
        gs.info('Date Range: ' + startDate + ' to ' + endDate);
        gs.info('Dry Run: ' + this.DRY_RUN);
        gs.info('');
        
        var gr = new GlideRecord('sc_req_item');
        gr.addQuery('cat_item', this.CATALOG_ITEM_SYS_ID);
        gr.addQuery('sys_created_on', '>=', startDate);
        gr.addQuery('sys_created_on', '<=', endDate + ' 23:59:59');
        gr.query();
        
        this._processRecords(gr);
    },
    
    /**
     * Delete RITMs with QIDs matching a pattern
     * @param {string} qidPattern - QID pattern (e.g., '9000' to match 90001, 90002, etc.)
     */
    deleteByQIDPattern: function(qidPattern) {
        gs.info('=== QUALYS CLEANUP: QID Pattern ===');
        gs.info('Catalog Item: ' + this.CATALOG_ITEM_SYS_ID);
        gs.info('QID Pattern: ' + qidPattern);
        gs.info('Dry Run: ' + this.DRY_RUN);
        gs.info('');
        
        var gr = new GlideRecord('sc_req_item');
        gr.addQuery('cat_item', this.CATALOG_ITEM_SYS_ID);
        gr.query();
        
        var matchedRecords = [];
        while (gr.next()) {
            var qid = gr.variables.identified_qid_s ? gr.variables.identified_qid_s.toString() : '';
            if (qid.indexOf(qidPattern) !== -1) {
                matchedRecords.push(gr.sys_id.toString());
            }
        }
        
        gs.info('Found ' + matchedRecords.length + ' RITMs matching QID pattern');
        
        // Process matched records
        for (var i = 0; i < matchedRecords.length; i++) {
            var ritm = new GlideRecord('sc_req_item');
            if (ritm.get(matchedRecords[i])) {
                this._deleteRITM(ritm);
            }
        }
        
        this._cleanupEmptyRequests();
        this._printSummary();
    },
    
    /**
     * Delete only test RITMs (QID starts with TEST_)
     */
    deleteTestRITMs: function() {
        gs.info('=== QUALYS CLEANUP: Test RITMs Only ===');
        gs.info('Looking for QIDs starting with TEST_');
        gs.info('Dry Run: ' + this.DRY_RUN);
        gs.info('');
        
        this.deleteByQIDPattern('TEST_');
    },
    
    /**
     * Delete RITMs by state
     * @param {string} state - State value (e.g., 'open', 'closed', 'all')
     */
    deleteByState: function(state) {
        gs.info('=== QUALYS CLEANUP: By State ===');
        gs.info('Catalog Item: ' + this.CATALOG_ITEM_SYS_ID);
        gs.info('State Filter: ' + state);
        gs.info('Dry Run: ' + this.DRY_RUN);
        gs.info('');
        
        var gr = new GlideRecord('sc_req_item');
        gr.addQuery('cat_item', this.CATALOG_ITEM_SYS_ID);
        
        if (state === 'open') {
            gr.addQuery('state', 'NOT IN', '3,4,7');  // Not closed, cancelled, or complete
        } else if (state === 'closed') {
            gr.addQuery('state', 'IN', '3,4,7');  // Closed, cancelled, or complete
        }
        // 'all' = no state filter
        
        gr.query();
        
        this._processRecords(gr);
    },
    
    // ============================================================
    // INTERNAL METHODS
    // ============================================================
    
    /**
     * Process and delete records from a GlideRecord query
     */
    _processRecords: function(gr) {
        var count = gr.getRowCount();
        gs.info('Found ' + count + ' RITMs');
        
        if (count === 0) {
            gs.info('Nothing to delete.');
            return;
        }
        
        if (count > this.MAX_DELETE_LIMIT) {
            gs.warn('Record count (' + count + ') exceeds MAX_DELETE_LIMIT (' + this.MAX_DELETE_LIMIT + ')');
            gs.warn('Limiting to first ' + this.MAX_DELETE_LIMIT + ' records');
        }
        
        gs.info('');
        gs.info('--- RITM Details ---');
        
        var processed = 0;
        while (gr.next() && processed < this.MAX_DELETE_LIMIT) {
            this._deleteRITM(gr);
            processed++;
        }
        
        // Cleanup empty parent requests
        this._cleanupEmptyRequests();
        
        // Print summary
        this._printSummary();
    },
    
    /**
     * Delete a single RITM
     */
    _deleteRITM: function(gr) {
        var ritmNumber = gr.number.toString();
        var requestId = gr.request.toString();
        var qid = gr.variables.identified_qid_s ? gr.variables.identified_qid_s.toString() : 'N/A';
        var state = gr.state.getDisplayValue();
        var created = gr.sys_created_on.toString();
        
        gs.info('RITM: ' + ritmNumber + ' | QID: ' + qid + ' | State: ' + state + ' | Created: ' + created);
        
        // Track parent request for cleanup
        if (requestId && this.deletedRequests.indexOf(requestId) === -1) {
            this.deletedRequests.push(requestId);
        }
        
        if (this.DRY_RUN) {
            this.deletedRitms.push(ritmNumber + ' (dry run)');
        } else {
            try {
                gr.deleteRecord();
                this.deletedRitms.push(ritmNumber);
            } catch (ex) {
                this.errors.push('Failed to delete ' + ritmNumber + ': ' + ex.getMessage());
            }
        }
    },
    
    /**
     * Clean up parent requests that have no remaining items
     */
    _cleanupEmptyRequests: function() {
        if (this.deletedRequests.length === 0) {
            return;
        }
        
        gs.info('');
        gs.info('--- Checking Parent Requests ---');
        
        for (var i = 0; i < this.deletedRequests.length; i++) {
            var reqId = this.deletedRequests[i];
            
            var reqGr = new GlideRecord('sc_request');
            if (reqGr.get(reqId)) {
                // Check if request has any remaining items
                var itemCheck = new GlideRecord('sc_req_item');
                itemCheck.addQuery('request', reqId);
                itemCheck.query();
                
                var remainingItems = itemCheck.getRowCount();
                
                if (remainingItems === 0 || this.DRY_RUN) {
                    gs.info('Request: ' + reqGr.number + ' | Remaining Items: ' + remainingItems);
                    
                    if (remainingItems === 0) {
                        if (this.DRY_RUN) {
                            gs.info('  Would delete (empty request)');
                        } else {
                            try {
                                reqGr.deleteRecord();
                                gs.info('  Deleted (empty request)');
                            } catch (ex) {
                                this.errors.push('Failed to delete request ' + reqGr.number + ': ' + ex.getMessage());
                            }
                        }
                    }
                }
            }
        }
    },
    
    /**
     * Print cleanup summary
     */
    _printSummary: function() {
        gs.info('');
        gs.info('=== CLEANUP SUMMARY ===');
        gs.info('Mode: ' + (this.DRY_RUN ? 'DRY RUN (no changes made)' : 'LIVE (records deleted)'));
        gs.info('RITMs processed: ' + this.deletedRitms.length);
        gs.info('Parent requests checked: ' + this.deletedRequests.length);
        
        if (this.errors.length > 0) {
            gs.info('');
            gs.info('--- Errors ---');
            for (var i = 0; i < this.errors.length; i++) {
                gs.error(this.errors[i]);
            }
        }
        
        if (this.DRY_RUN) {
            gs.info('');
            gs.info('*** This was a DRY RUN. No records were deleted. ***');
            gs.info('*** Set DRY_RUN = false to actually delete records. ***');
        }
    },
    
    type: 'QualysCleanup'
};

// ============================================================
// USAGE EXAMPLES (uncomment one to run)
// ============================================================

var cleanup = new QualysCleanup();

// IMPORTANT: Update the catalog item sys_id first!
// cleanup.CATALOG_ITEM_SYS_ID = 'your_actual_sys_id_here';

// Preview what would be deleted (DRY RUN)
// cleanup.DRY_RUN = true;
// cleanup.deleteAll();

// Delete all RITMs for this catalog item
// cleanup.DRY_RUN = false;
// cleanup.deleteAll();

// Delete only today's RITMs
// cleanup.DRY_RUN = false;
// cleanup.deleteTodayOnly();

// Delete RITMs from specific date range
// cleanup.DRY_RUN = false;
// cleanup.deleteByDateRange('2024-01-01', '2024-01-15');

// Delete RITMs with specific QID pattern
// cleanup.DRY_RUN = false;
// cleanup.deleteByQIDPattern('90007');

// Delete only test RITMs (QID starts with TEST_)
// cleanup.DRY_RUN = false;
// cleanup.deleteTestRITMs();

// Delete only open RITMs
// cleanup.DRY_RUN = false;
// cleanup.deleteByState('open');

// Delete only closed RITMs
// cleanup.DRY_RUN = false;
// cleanup.deleteByState('closed');
