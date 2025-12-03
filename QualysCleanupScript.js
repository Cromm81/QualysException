/**
 * Qualys RITM Cleanup Script
 * 
 * HOW TO USE:
 * 1. Update CATALOG_ITEM_SYS_ID below
 * 2. Run in Scripts - Background
 * 3. By default, runs DRY RUN showing what would be deleted
 * 4. To actually delete, change DELETE_MODE to true
 */

// ============================================================
// CONFIGURATION - UPDATE THESE
// ============================================================

var CATALOG_ITEM_SYS_ID = 'YOUR_CATALOG_ITEM_SYS_ID';  // <-- PUT YOUR SYS_ID HERE

var DELETE_MODE = false;  // false = DRY RUN (safe), true = ACTUALLY DELETE

var FILTER = 'all';  // Options: 'all', 'today', 'test_only'

// ============================================================
// SCRIPT STARTS HERE - DO NOT MODIFY BELOW
// ============================================================

gs.info('');
gs.info('╔════════════════════════════════════════════════════════════╗');
gs.info('║           QUALYS RITM CLEANUP SCRIPT                       ║');
gs.info('╚════════════════════════════════════════════════════════════╝');
gs.info('');
gs.info('Configuration:');
gs.info('  Catalog Item: ' + CATALOG_ITEM_SYS_ID);
gs.info('  Filter: ' + FILTER);
gs.info('  Mode: ' + (DELETE_MODE ? '*** DELETE MODE - WILL DELETE RECORDS ***' : 'DRY RUN (safe preview)'));
gs.info('');

// Validate sys_id
if (CATALOG_ITEM_SYS_ID === 'YOUR_CATALOG_ITEM_SYS_ID' || !CATALOG_ITEM_SYS_ID) {
    gs.error('ERROR: You must set CATALOG_ITEM_SYS_ID before running this script!');
    gs.info('');
    gs.info('To find your catalog item sys_id, run this:');
    gs.info('  var gr = new GlideRecord("sc_cat_item");');
    gs.info('  gr.addQuery("name", "CONTAINS", "exception");');
    gs.info('  gr.query();');
    gs.info('  while (gr.next()) gs.info(gr.name + " = " + gr.sys_id);');
    gs.info('');
} else {
    // Build query
    var gr = new GlideRecord('sc_req_item');
    gr.addQuery('cat_item', CATALOG_ITEM_SYS_ID);
    
    if (FILTER === 'today') {
        gr.addQuery('sys_created_on', '>=', gs.beginningOfToday());
        gs.info('Filtering: Only RITMs created TODAY');
    } else if (FILTER === 'test_only') {
        gs.info('Filtering: Only RITMs with QID starting with TEST_');
    }
    
    gr.query();
    
    var totalCount = gr.getRowCount();
    gs.info('');
    gs.info('Found ' + totalCount + ' RITMs matching criteria');
    gs.info('');
    
    if (totalCount === 0) {
        gs.info('Nothing to clean up!');
    } else {
        gs.info('─────────────────────────────────────────────────────────────');
        gs.info('RITM Number       | QID                | State      | Created');
        gs.info('─────────────────────────────────────────────────────────────');
        
        var deleteCount = 0;
        var skipCount = 0;
        var requestsToCheck = [];
        
        while (gr.next()) {
            var ritmNum = gr.number.toString();
            var qid = gr.variables.identified_qid_s ? gr.variables.identified_qid_s.toString() : 'N/A';
            var state = gr.state.getDisplayValue();
            var created = gr.sys_created_on.toString().substring(0, 10);
            var requestId = gr.request.toString();
            
            // Apply test_only filter
            if (FILTER === 'test_only' && qid.indexOf('TEST_') !== 0) {
                skipCount++;
                continue;
            }
            
            // Pad for alignment
            while (ritmNum.length < 17) ritmNum += ' ';
            while (qid.length < 20) qid += ' ';
            while (state.length < 10) state += ' ';
            
            gs.info(ritmNum + '| ' + qid + '| ' + state + '| ' + created);
            
            // Track request for cleanup
            if (requestId && requestsToCheck.indexOf(requestId) === -1) {
                requestsToCheck.push(requestId);
            }
            
            // Delete if in delete mode
            if (DELETE_MODE) {
                gr.deleteRecord();
                deleteCount++;
            } else {
                deleteCount++;
            }
        }
        
        gs.info('─────────────────────────────────────────────────────────────');
        gs.info('');
        
        if (FILTER === 'test_only') {
            gs.info('Skipped ' + skipCount + ' non-test RITMs');
        }
        
        // Clean up empty requests
        if (DELETE_MODE && requestsToCheck.length > 0) {
            gs.info('Checking ' + requestsToCheck.length + ' parent requests...');
            var reqDeleted = 0;
            
            for (var i = 0; i < requestsToCheck.length; i++) {
                var reqGr = new GlideRecord('sc_request');
                if (reqGr.get(requestsToCheck[i])) {
                    var itemCheck = new GlideRecord('sc_req_item');
                    itemCheck.addQuery('request', requestsToCheck[i]);
                    itemCheck.query();
                    
                    if (itemCheck.getRowCount() === 0) {
                        gs.info('  Deleted empty request: ' + reqGr.number);
                        reqGr.deleteRecord();
                        reqDeleted++;
                    }
                }
            }
            gs.info('Deleted ' + reqDeleted + ' empty parent requests');
            gs.info('');
        }
        
        // Summary
        gs.info('╔════════════════════════════════════════════════════════════╗');
        if (DELETE_MODE) {
            gs.info('║  DELETED ' + deleteCount + ' RITMs                                       ');
        } else {
            gs.info('║  WOULD DELETE ' + deleteCount + ' RITMs (DRY RUN)                        ');
            gs.info('║                                                            ║');
            gs.info('║  To actually delete, change DELETE_MODE to true            ║');
        }
        gs.info('╚════════════════════════════════════════════════════════════╝');
    }
}

gs.info('');
gs.info('Script complete.');
