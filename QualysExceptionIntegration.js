/**
 * QualysExceptionIntegration
 * 
 * Script Include for integrating Qualys vulnerability data with ServiceNow
 * Exception Management catalog items.
 * 
 * Features:
 * - Creates one RITM per QID containing all affected hosts
 * - Updates existing RITMs with host changes on subsequent runs
 * - Handles hosts not in CMDB via text field fallback
 * - Batched CVE lookups for performance
 * - Lifecycle test mode for validation
 * - Flags RITMs for closure when all hosts remediated
 * 
 * Usage:
 *   var integration = new QualysExceptionIntegration();
 *   integration.run();
 * 
 * Lifecycle Test:
 *   var integration = new QualysExceptionIntegration();
 *   integration.runLifecycleTest();
 */

var QualysExceptionIntegration = Class.create();
QualysExceptionIntegration.prototype = {
    
    // ============================================================
    // CONFIGURATION - UPDATE THESE VALUES
    // ============================================================
    
    QUALYS_API_URL: 'https://qualysapi.qg1.apps.qualys.ca',
    QUALYS_USERNAME: 'YOUR_QUALYS_USERNAME',      // TODO: Replace
    QUALYS_PASSWORD: 'YOUR_QUALYS_PASSWORD',      // TODO: Replace
    
    CATALOG_ITEM_SYS_ID: 'YOUR_CATALOG_ITEM_SYS_ID',  // TODO: Replace
    TEAM_SYS_ID: 'YOUR_TEAM_SYS_ID',                   // TODO: Replace
    
    // Exception request defaults
    EXCEPTION_DURATION_MONTHS: 6,
    
    // ============================================================
    // PERFORMANCE & MODE OPTIONS
    // ============================================================
    
    // Test mode - limits data for faster testing
    TEST_MODE: false,
    
    // Maximum hosts to retrieve from Qualys (0 = no limit)
    TRUNCATION_LIMIT: 0,
    
    // Maximum QIDs to process per run (0 = no limit)
    MAX_QIDS_PER_RUN: 0,
    
    // Skip Qualys KB lookups (faster, but no CVE/CVSS details)
    SKIP_KB_LOOKUPS: false,
    
    // Batch size for KB lookups (max QIDs per API call)
    KB_BATCH_SIZE: 50,
    
    // Log level: 'debug', 'info', 'warn', 'error'
    LOG_LEVEL: 'info',
    
    // Test QID prefix for lifecycle testing
    TEST_QID_PREFIX: 'TEST_QID_',
    
    // ============================================================
    // INITIALIZATION
    // ============================================================
    
    initialize: function() {
        this.log = new GSLog('com.qualys.integration', 'QualysExceptionIntegration');
        this.log.setLevel(this.LOG_LEVEL);
        this.startTime = new Date().getTime();
        this.vulnDetailsCache = {};  // Cache for KB lookup results
    },
    
    /**
     * Get elapsed time in seconds
     */
    _getElapsedSeconds: function() {
        return Math.round((new Date().getTime() - this.startTime) / 1000);
    },
    
    // ============================================================
    // MAIN ENTRY POINT
    // ============================================================
    
    /**
     * Main execution method - called by Scheduled Job
     */
    run: function() {
        this.log.info('=== Qualys Exception Integration Started ===');
        this.log.info('Test Mode: ' + this.TEST_MODE);
        this.log.info('Truncation Limit: ' + this.TRUNCATION_LIMIT);
        this.log.info('Max QIDs per run: ' + this.MAX_QIDS_PER_RUN);
        this.log.info('Skip KB Lookups: ' + this.SKIP_KB_LOOKUPS);
        
        try {
            // Step 1: Pull vulnerabilities from Qualys
            var vulnData = this._pullVulnerabilities();
            if (!vulnData || vulnData.length === 0) {
                this.log.info('No vulnerabilities returned from Qualys');
                return { success: true, created: 0, updated: 0, message: 'No vulnerabilities found' };
            }
            
            this.log.info('Elapsed: ' + this._getElapsedSeconds() + 's - Pulled ' + vulnData.length + ' detections');
            
            // Step 2: Group vulnerabilities by QID
            var groupedVulns = this._groupByQID(vulnData);
            var qidCount = Object.keys(groupedVulns).length;
            this.log.info('Grouped into ' + qidCount + ' unique QIDs');
            
            // Step 3: Batch fetch KB details for all QIDs (if not skipped)
            if (!this.SKIP_KB_LOOKUPS) {
                this._batchFetchVulnDetails(Object.keys(groupedVulns));
                this.log.info('Elapsed: ' + this._getElapsedSeconds() + 's - Fetched KB details');
            }
            
            // Step 4: Apply QID limit if set
            var qidsToProcess = Object.keys(groupedVulns);
            if (this.MAX_QIDS_PER_RUN > 0 && qidsToProcess.length > this.MAX_QIDS_PER_RUN) {
                this.log.info('Limiting to ' + this.MAX_QIDS_PER_RUN + ' QIDs (out of ' + qidsToProcess.length + ')');
                qidsToProcess = qidsToProcess.slice(0, this.MAX_QIDS_PER_RUN);
            }
            
            // Step 5: Process each QID - create or update RITMs
            var stats = {
                created: 0,
                updated: 0,
                flaggedForClosure: 0,
                skipped: 0,
                errors: 0
            };
            
            for (var i = 0; i < qidsToProcess.length; i++) {
                var qid = qidsToProcess[i];
                
                // Progress logging every 10 QIDs
                if (i > 0 && i % 10 === 0) {
                    this.log.info('Progress: ' + i + '/' + qidsToProcess.length + ' QIDs (' + this._getElapsedSeconds() + 's)');
                }
                
                try {
                    var result = this._processQID(qid, groupedVulns[qid]);
                    if (result === 'created') {
                        stats.created++;
                    } else if (result === 'updated') {
                        stats.updated++;
                    } else if (result === 'flagged') {
                        stats.flaggedForClosure++;
                    } else if (result === 'skipped') {
                        stats.skipped++;
                    }
                } catch (ex) {
                    this.log.error('Error processing QID ' + qid + ': ' + ex.getMessage());
                    stats.errors++;
                }
            }
            
            this.log.info('=== Integration Complete ===');
            this.log.info('Total time: ' + this._getElapsedSeconds() + ' seconds');
            this.log.info('Created: ' + stats.created + ' | Updated: ' + stats.updated + 
                         ' | Flagged for closure: ' + stats.flaggedForClosure +
                         ' | Skipped: ' + stats.skipped + ' | Errors: ' + stats.errors);
            
            if (this.MAX_QIDS_PER_RUN > 0 && qidsToProcess.length < qidCount) {
                this.log.info('NOTE: ' + (qidCount - qidsToProcess.length) + ' QIDs remaining - run again to process more');
            }
            
            return stats;
            
        } catch (ex) {
            this.log.error('Integration failed: ' + ex.getMessage());
            return { success: false, error: ex.getMessage() };
        }
    },
    
    // ============================================================
    // LIFECYCLE TEST METHOD
    // ============================================================
    
    /**
     * Run automated lifecycle test
     * Tests: Creation -> Update (partial remediation) -> Update (new host) -> Flag for closure -> Cleanup
     */
    runLifecycleTest: function() {
        this.log.info('');
        this.log.info('╔══════════════════════════════════════════════════════════════╗');
        this.log.info('║           QUALYS INTEGRATION LIFECYCLE TEST                  ║');
        this.log.info('╚══════════════════════════════════════════════════════════════╝');
        this.log.info('');
        
        var testQID = this.TEST_QID_PREFIX + new Date().getTime();
        var testResults = {
            stage1: false,
            stage2: false,
            stage3: false,
            stage4: false,
            cleanup: false
        };
        var ritmSysId = null;
        
        try {
            // ==================== STAGE 1: Initial Detection ====================
            this.log.info('');
            this.log.info('═══ STAGE 1: Initial Detection ═══');
            this.log.info('Creating RITM with 3 hosts for QID: ' + testQID);
            
            var stage1Data = {
                qid: testQID,
                severity: '4',
                hosts: [
                    { ip: '10.0.0.1', dns: 'test-host-A', hostname: 'test-host-A', assetId: 'TEST001', os: 'Windows Server 2019', status: 'Active' },
                    { ip: '10.0.0.2', dns: 'test-host-B', hostname: 'test-host-B', assetId: 'TEST002', os: 'Windows Server 2019', status: 'Active' },
                    { ip: '10.0.0.3', dns: 'test-host-C', hostname: 'test-host-C', assetId: 'TEST003', os: 'Windows Server 2019', status: 'Active' }
                ]
            };
            
            // Mock KB details
            this.vulnDetailsCache[testQID] = {
                title: 'Test Vulnerability for Lifecycle Testing',
                cveList: ['CVE-2024-TEST1', 'CVE-2024-TEST2'],
                cvssBase: '6.5',
                cvss3Base: '7.5',
                solution: 'Apply vendor patch',
                diagnosis: 'This is a test vulnerability'
            };
            
            var result1 = this._processQID(testQID, stage1Data);
            
            // Verify Stage 1
            var ritm1 = this._findExistingRITM(testQID);
            if (ritm1 && result1 === 'created') {
                ritmSysId = ritm1.sys_id.toString();
                this.log.info('✓ RITM created: ' + ritm1.number);
                this.log.info('✓ Result: ' + result1);
                testResults.stage1 = true;
            } else {
                this.log.error('✗ Stage 1 FAILED - RITM not created properly');
            }
            
            // ==================== STAGE 2: Partial Remediation ====================
            this.log.info('');
            this.log.info('═══ STAGE 2: Partial Remediation ═══');
            this.log.info('Removing host C (simulating remediation)');
            
            var stage2Data = {
                qid: testQID,
                severity: '4',
                hosts: [
                    { ip: '10.0.0.1', dns: 'test-host-A', hostname: 'test-host-A', assetId: 'TEST001', os: 'Windows Server 2019', status: 'Active' },
                    { ip: '10.0.0.2', dns: 'test-host-B', hostname: 'test-host-B', assetId: 'TEST002', os: 'Windows Server 2019', status: 'Active' }
                    // Host C removed - simulating remediation
                ]
            };
            
            var result2 = this._processQID(testQID, stage2Data);
            
            if (result2 === 'updated') {
                this.log.info('✓ RITM updated');
                this.log.info('✓ Check work notes for "test-host-C" remediation message');
                testResults.stage2 = true;
            } else {
                this.log.error('✗ Stage 2 FAILED - Expected "updated", got "' + result2 + '"');
            }
            
            // ==================== STAGE 3: New Host Affected ====================
            this.log.info('');
            this.log.info('═══ STAGE 3: New Host Affected ═══');
            this.log.info('Adding host D (new detection)');
            
            var stage3Data = {
                qid: testQID,
                severity: '4',
                hosts: [
                    { ip: '10.0.0.1', dns: 'test-host-A', hostname: 'test-host-A', assetId: 'TEST001', os: 'Windows Server 2019', status: 'Active' },
                    { ip: '10.0.0.2', dns: 'test-host-B', hostname: 'test-host-B', assetId: 'TEST002', os: 'Windows Server 2019', status: 'Active' },
                    { ip: '10.0.0.4', dns: 'test-host-D', hostname: 'test-host-D', assetId: 'TEST004', os: 'Windows Server 2019', status: 'Active' }
                ]
            };
            
            var result3 = this._processQID(testQID, stage3Data);
            
            if (result3 === 'updated') {
                this.log.info('✓ RITM updated');
                this.log.info('✓ Check work notes for "test-host-D" added message');
                testResults.stage3 = true;
            } else {
                this.log.error('✗ Stage 3 FAILED - Expected "updated", got "' + result3 + '"');
            }
            
            // ==================== STAGE 4: Full Remediation ====================
            this.log.info('');
            this.log.info('═══ STAGE 4: Full Remediation ═══');
            this.log.info('Removing all hosts (simulating full remediation)');
            
            var stage4Data = {
                qid: testQID,
                severity: '4',
                hosts: []  // All hosts remediated
            };
            
            var result4 = this._processQID(testQID, stage4Data);
            
            if (result4 === 'flagged') {
                this.log.info('✓ RITM flagged for closure');
                this.log.info('✓ Check work notes for "ALL HOSTS REMEDIATED" message');
                testResults.stage4 = true;
            } else {
                this.log.error('✗ Stage 4 FAILED - Expected "flagged", got "' + result4 + '"');
            }
            
            // ==================== CLEANUP ====================
            this.log.info('');
            this.log.info('═══ CLEANUP ═══');
            
            if (ritmSysId) {
                var ritmToDelete = new GlideRecord('sc_req_item');
                if (ritmToDelete.get(ritmSysId)) {
                    var ritmNumber = ritmToDelete.number.toString();
                    var requestId = ritmToDelete.request.toString();
                    
                    ritmToDelete.deleteRecord();
                    this.log.info('✓ Deleted test RITM: ' + ritmNumber);
                    
                    // Delete parent request if empty
                    var reqGr = new GlideRecord('sc_request');
                    if (reqGr.get(requestId)) {
                        var itemCheck = new GlideRecord('sc_req_item');
                        itemCheck.addQuery('request', requestId);
                        itemCheck.query();
                        
                        if (itemCheck.getRowCount() === 0) {
                            reqGr.deleteRecord();
                            this.log.info('✓ Deleted empty parent request');
                        }
                    }
                    
                    testResults.cleanup = true;
                }
            }
            
        } catch (ex) {
            this.log.error('Lifecycle test error: ' + ex.getMessage());
        }
        
        // ==================== SUMMARY ====================
        this.log.info('');
        this.log.info('╔══════════════════════════════════════════════════════════════╗');
        this.log.info('║                    TEST RESULTS SUMMARY                      ║');
        this.log.info('╚══════════════════════════════════════════════════════════════╝');
        this.log.info('');
        this.log.info('Stage 1 (Initial Detection):    ' + (testResults.stage1 ? '✓ PASSED' : '✗ FAILED'));
        this.log.info('Stage 2 (Partial Remediation):  ' + (testResults.stage2 ? '✓ PASSED' : '✗ FAILED'));
        this.log.info('Stage 3 (New Host Affected):    ' + (testResults.stage3 ? '✓ PASSED' : '✗ FAILED'));
        this.log.info('Stage 4 (Full Remediation):     ' + (testResults.stage4 ? '✓ PASSED' : '✗ FAILED'));
        this.log.info('Cleanup:                        ' + (testResults.cleanup ? '✓ PASSED' : '✗ FAILED'));
        this.log.info('');
        
        var allPassed = testResults.stage1 && testResults.stage2 && testResults.stage3 && testResults.stage4 && testResults.cleanup;
        this.log.info('Overall Result: ' + (allPassed ? '✓ ALL TESTS PASSED' : '✗ SOME TESTS FAILED'));
        this.log.info('');
        
        return testResults;
    },
    
    // ============================================================
    // QUALYS API METHODS
    // ============================================================
    
    /**
     * Pull vulnerability detections from Qualys API
     * @returns {Array} Array of vulnerability detection objects
     */
    _pullVulnerabilities: function() {
        this.log.info('Pulling vulnerabilities from Qualys API...');
        
        var endpoint = this.QUALYS_API_URL + '/api/2.0/fo/asset/host/vm/detection/';
        
        var request = new sn_ws.RESTMessageV2();
        request.setEndpoint(endpoint);
        request.setHttpMethod('POST');
        request.setBasicAuth(this.QUALYS_USERNAME, this.QUALYS_PASSWORD);
        request.setRequestHeader('X-Requested-With', 'ServiceNow');
        request.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
        
        // Request parameters
        var params = 'action=list&show_asset_id=1&status=New,Active,Re-Opened';
        
        // Add truncation limit if set
        if (this.TRUNCATION_LIMIT > 0) {
            params += '&truncation_limit=' + this.TRUNCATION_LIMIT;
            this.log.info('Using truncation limit: ' + this.TRUNCATION_LIMIT + ' hosts');
        }
        
        request.setRequestBody(params);
        
        var response;
        try {
            response = request.execute();
        } catch (ex) {
            this.log.error('Exception during API call: ' + ex.getMessage());
            return null;
        }
        
        var httpStatus = response.getStatusCode();
        var body = response.getBody();
        
        this.log.info('HTTP Status: ' + httpStatus);
        this.log.info('Response size: ' + (body ? Math.round(body.length / 1024) + ' KB' : '0 KB'));
        
        if (httpStatus !== 200) {
            this.log.error('Qualys API returned status: ' + httpStatus);
            return null;
        }
        
        if (!body || body.trim() === '') {
            this.log.error('Qualys returned empty response body');
            return null;
        }
        
        return this._parseQualysResponse(body);
    },
    
    /**
     * Parse Qualys XML response into structured data using regex (reliable method)
     * @param {string} xmlBody - Raw XML response from Qualys
     * @returns {Array} Array of vulnerability objects
     */
    _parseQualysResponse: function(xmlBody) {
        var vulns = [];
        
        this.log.debug('Starting XML parsing...');
        
        // Use regex parsing for reliability with large documents
        var hostRegex = /<HOST>([\s\S]*?)<\/HOST>/g;
        var hostMatch;
        var hostCount = 0;
        
        while ((hostMatch = hostRegex.exec(xmlBody)) !== null) {
            hostCount++;
            var hostBlock = hostMatch[1];
            
            var hostInfo = {
                ip: this._extractTag(hostBlock, 'IP'),
                dns: this._cleanCDATA(this._extractTag(hostBlock, 'DNS')),
                assetId: this._extractTag(hostBlock, 'ASSET_ID'),
                os: this._cleanCDATA(this._extractTag(hostBlock, 'OS')),
                hostname: this._cleanCDATA(this._extractTag(hostBlock, 'HOSTNAME'))
            };
            
            // Use DNS as hostname fallback
            if (!hostInfo.hostname && hostInfo.dns) {
                hostInfo.hostname = hostInfo.dns;
            }
            
            // Extract DETECTION blocks within this host
            var detRegex = /<DETECTION>([\s\S]*?)<\/DETECTION>/g;
            var detMatch;
            
            while ((detMatch = detRegex.exec(hostBlock)) !== null) {
                var detBlock = detMatch[1];
                
                var vuln = {
                    host: hostInfo,
                    qid: this._extractTag(detBlock, 'QID'),
                    severity: this._extractTag(detBlock, 'SEVERITY'),
                    status: this._extractTag(detBlock, 'STATUS'),
                    firstFound: this._extractTag(detBlock, 'FIRST_FOUND_DATETIME'),
                    lastFound: this._extractTag(detBlock, 'LAST_FOUND_DATETIME'),
                    results: this._cleanCDATA(this._extractTag(detBlock, 'RESULTS'))
                };
                
                vulns.push(vuln);
            }
        }
        
        this.log.info('Parsed ' + hostCount + ' hosts, ' + vulns.length + ' vulnerability detections');
        return vulns;
    },
    
    /**
     * Batch fetch vulnerability details from Qualys KnowledgeBase
     * @param {Array} qidList - Array of QIDs to fetch
     */
    _batchFetchVulnDetails: function(qidList) {
        this.log.info('Fetching KB details for ' + qidList.length + ' QIDs in batches of ' + this.KB_BATCH_SIZE);
        
        for (var i = 0; i < qidList.length; i += this.KB_BATCH_SIZE) {
            var batch = qidList.slice(i, Math.min(i + this.KB_BATCH_SIZE, qidList.length));
            this._fetchKBBatch(batch);
            
            if (i > 0 && i % 100 === 0) {
                this.log.debug('KB fetch progress: ' + i + '/' + qidList.length);
            }
        }
        
        this.log.info('KB details cached for ' + Object.keys(this.vulnDetailsCache).length + ' QIDs');
    },
    
    /**
     * Fetch KB details for a batch of QIDs
     * @param {Array} qidBatch - Array of QIDs
     */
    _fetchKBBatch: function(qidBatch) {
        var endpoint = this.QUALYS_API_URL + '/api/2.0/fo/knowledge_base/vuln/';
        
        var request = new sn_ws.RESTMessageV2();
        request.setEndpoint(endpoint);
        request.setHttpMethod('POST');
        request.setBasicAuth(this.QUALYS_USERNAME, this.QUALYS_PASSWORD);
        request.setRequestHeader('X-Requested-With', 'ServiceNow');
        request.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
        
        var params = 'action=list&ids=' + qidBatch.join(',');
        request.setRequestBody(params);
        
        try {
            var response = request.execute();
            
            if (response.getStatusCode() !== 200) {
                this.log.warn('KB batch fetch failed with status: ' + response.getStatusCode());
                return;
            }
            
            var body = response.getBody();
            this._parseKBResponse(body);
            
        } catch (ex) {
            this.log.warn('KB batch fetch error: ' + ex.getMessage());
        }
    },
    
    /**
     * Parse KB response and populate cache
     * @param {string} xmlBody - KB API response
     */
    _parseKBResponse: function(xmlBody) {
        var vulnRegex = /<VULN>([\s\S]*?)<\/VULN>/g;
        var vulnMatch;
        
        while ((vulnMatch = vulnRegex.exec(xmlBody)) !== null) {
            var vulnBlock = vulnMatch[1];
            var qid = this._extractTag(vulnBlock, 'QID');
            
            if (qid) {
                // Extract CVE list
                var cveList = [];
                var cveRegex = /<CVE_LIST>[\s\S]*?<ID>([\s\S]*?)<\/ID>[\s\S]*?<\/CVE_LIST>/g;
                var cveMatch;
                while ((cveMatch = cveRegex.exec(vulnBlock)) !== null) {
                    cveList.push(this._cleanCDATA(cveMatch[1]));
                }
                
                // Alternative CVE extraction
                if (cveList.length === 0) {
                    var altCveRegex = /<ID>CVE[^<]*<\/ID>/g;
                    var altMatch;
                    while ((altMatch = altCveRegex.exec(vulnBlock)) !== null) {
                        var cve = altMatch[0].replace(/<\/?ID>/g, '');
                        cveList.push(cve);
                    }
                }
                
                this.vulnDetailsCache[qid] = {
                    title: this._cleanCDATA(this._extractTag(vulnBlock, 'TITLE')),
                    cveList: cveList,
                    cvssBase: this._extractTag(vulnBlock, 'CVSS/BASE') || this._extractTagPath(vulnBlock, 'CVSS', 'BASE'),
                    cvss3Base: this._extractTag(vulnBlock, 'CVSS_V3/BASE') || this._extractTagPath(vulnBlock, 'CVSS_V3', 'BASE'),
                    solution: this._cleanCDATA(this._extractTag(vulnBlock, 'SOLUTION')),
                    diagnosis: this._cleanCDATA(this._extractTag(vulnBlock, 'DIAGNOSIS'))
                };
            }
        }
    },
    
    /**
     * Get cached vulnerability details
     * @param {string} qid - QID to lookup
     * @returns {Object|null} Vulnerability details
     */
    _getVulnDetails: function(qid) {
        return this.vulnDetailsCache[qid] || null;
    },
    
    // ============================================================
    // DATA PROCESSING METHODS
    // ============================================================
    
    /**
     * Group vulnerabilities by QID
     * @param {Array} vulnData - Array of vulnerability objects
     * @returns {Object} Object keyed by QID with array of hosts
     */
    _groupByQID: function(vulnData) {
        var grouped = {};
        
        for (var i = 0; i < vulnData.length; i++) {
            var vuln = vulnData[i];
            var qid = vuln.qid;
            
            if (!grouped[qid]) {
                grouped[qid] = {
                    qid: qid,
                    severity: vuln.severity,
                    hosts: []
                };
            }
            
            grouped[qid].hosts.push({
                ip: vuln.host.ip,
                dns: vuln.host.dns,
                hostname: vuln.host.hostname,
                assetId: vuln.host.assetId,
                os: vuln.host.os,
                status: vuln.status,
                firstFound: vuln.firstFound,
                lastFound: vuln.lastFound
            });
        }
        
        return grouped;
    },
    
    /**
     * Process a single QID - create or update RITM
     * @param {string} qid - Qualys QID
     * @param {Object} vulnGroup - Grouped vulnerability data
     * @returns {string} 'created', 'updated', 'flagged', or 'skipped'
     */
    _processQID: function(qid, vulnGroup) {
        // Check if RITM already exists for this QID (OPEN only)
        var existingRitm = this._findExistingRITM(qid);
        
        // Get vulnerability details from cache
        var vulnDetails = this._getVulnDetails(qid);
        
        // Check if all hosts are remediated
        if (vulnGroup.hosts.length === 0) {
            if (existingRitm) {
                // Flag existing RITM for closure
                this._flagRITMForClosure(existingRitm, qid);
                return 'flagged';
            } else {
                // No hosts and no RITM - nothing to do
                return 'skipped';
            }
        }
        
        if (existingRitm) {
            // Update existing RITM
            this._updateRITM(existingRitm, vulnGroup, vulnDetails);
            return 'updated';
        } else {
            // Create new RITM
            this._createRITM(qid, vulnGroup, vulnDetails);
            return 'created';
        }
    },
    
    // ============================================================
    // SERVICENOW RITM METHODS
    // ============================================================
    
    /**
     * Find existing OPEN RITM for a QID
     * @param {string} qid - Qualys QID
     * @returns {GlideRecord|null} RITM record or null if not found
     */
    _findExistingRITM: function(qid) {
        var gr = new GlideRecord('sc_req_item');
        gr.addQuery('cat_item', this.CATALOG_ITEM_SYS_ID);
        // Only find OPEN RITMs - exclude closed (3), cancelled (4), and completed (7)
        gr.addQuery('state', 'NOT IN', '3,4,7');
        gr.query();
        
        while (gr.next()) {
            var qidValue = gr.variables.identified_qid_s ? gr.variables.identified_qid_s.toString() : '';
            // Exact match only (not partial)
            if (qidValue === qid) {
                return gr;
            }
        }
        
        return null;
    },
    
    /**
     * Create new RITM for a QID
     * @param {string} qid - Qualys QID
     * @param {Object} vulnGroup - Grouped vulnerability data
     * @param {Object} vulnDetails - KB details for the vulnerability
     */
    _createRITM: function(qid, vulnGroup, vulnDetails) {
        this.log.info('Creating RITM for QID: ' + qid + ' (' + vulnGroup.hosts.length + ' hosts)');
        
        // Process hosts - separate CMDB-matched from unmatched
        var hostProcessing = this._processHosts(vulnGroup.hosts);
        
        // Calculate dates
        var today = new GlideDateTime();
        var endDate = new GlideDateTime();
        endDate.addMonthsUTC(this.EXCEPTION_DURATION_MONTHS);
        
        // Build justification text with all hosts
        var justification = this._buildJustification(qid, vulnGroup, vulnDetails, hostProcessing);
        
        // Create the catalog request
        var cart = new Cart();
        var item = cart.addItem(this.CATALOG_ITEM_SYS_ID);
        
        // Set variables
        cart.setVariable(item, 'identified_qid_s', qid);
        cart.setVariable(item, 'vulnerability_in_vuln_mgmt_platform', 'Yes');
        cart.setVariable(item, 'please_select_the_team_responsible_for_remediation', this.TEAM_SYS_ID);
        cart.setVariable(item, 'datefrom', today.getDate().toString());
        cart.setVariable(item, 'dateto', endDate.getDate().toString());
        cart.setVariable(item, 'justification_for_exception', justification);
        
        if (vulnDetails) {
            if (vulnDetails.cveList && vulnDetails.cveList.length > 0) {
                cart.setVariable(item, 'identified_cves', vulnDetails.cveList.join(', '));
            }
            var cvss = vulnDetails.cvss3Base || vulnDetails.cvssBase || '';
            cart.setVariable(item, 'highest_cvss', cvss);
        }
        
        // Set impacted systems (CMDB-matched hosts only)
        if (hostProcessing.matchedSysIds.length > 0) {
            cart.setVariable(item, 'impacted_system', hostProcessing.matchedSysIds.join(','));
        }
        
        // Submit the request
        var request = cart.placeOrder();
        
        // Get the RITM that was created
        var ritmGr = new GlideRecord('sc_req_item');
        ritmGr.addQuery('request', request.sys_id);
        ritmGr.query();
        
        if (ritmGr.next()) {
            // Add work note with summary
            var workNote = '=== QUALYS INTEGRATION: RITM CREATED ===\n\n';
            workNote += 'QID: ' + qid + '\n';
            if (vulnDetails && vulnDetails.title) {
                workNote += 'Title: ' + vulnDetails.title + '\n';
            }
            workNote += '\nTotal Hosts: ' + vulnGroup.hosts.length + '\n';
            workNote += 'CMDB-Linked: ' + hostProcessing.matchedSysIds.length + '\n';
            workNote += 'Not in CMDB: ' + hostProcessing.unmatchedHosts.length + '\n';
            
            if (hostProcessing.unmatchedHosts.length > 0) {
                workNote += '\n*** ATTENTION: ' + hostProcessing.unmatchedHosts.length + ' hosts not found in CMDB ***\n';
                workNote += 'See justification field for full host list.\n';
            }
            
            ritmGr.work_notes = workNote;
            ritmGr.update();
            
            this.log.info('Created RITM: ' + ritmGr.number);
        }
    },
    
    /**
     * Update existing RITM with new host information
     * @param {GlideRecord} ritmGr - Existing RITM record
     * @param {Object} vulnGroup - Current vulnerability data
     * @param {Object} vulnDetails - KB details for the vulnerability
     */
    _updateRITM: function(ritmGr, vulnGroup, vulnDetails) {
        this.log.info('Updating RITM: ' + ritmGr.number + ' for QID: ' + vulnGroup.qid);
        
        // Process current hosts
        var currentHostProcessing = this._processHosts(vulnGroup.hosts);
        
        // Get previous host list from RITM
        var prevHostSysIds = ritmGr.variables.impacted_system ? ritmGr.variables.impacted_system.toString() : '';
        var prevHostList = prevHostSysIds ? prevHostSysIds.split(',').filter(function(s) { return s; }) : [];
        
        // Calculate changes
        var addedHosts = [];
        var removedHosts = [];
        
        // Find added hosts (in current but not in previous)
        for (var i = 0; i < currentHostProcessing.matchedSysIds.length; i++) {
            if (prevHostList.indexOf(currentHostProcessing.matchedSysIds[i]) === -1) {
                addedHosts.push(currentHostProcessing.matchedSysIds[i]);
            }
        }
        
        // Find removed hosts (in previous but not in current)
        for (var j = 0; j < prevHostList.length; j++) {
            if (prevHostList[j] && currentHostProcessing.matchedSysIds.indexOf(prevHostList[j]) === -1) {
                removedHosts.push(prevHostList[j]);
            }
        }
        
        // Build work note
        var workNote = '=== QUALYS INTEGRATION UPDATE ===\n';
        workNote += 'Date: ' + new GlideDateTime().getDisplayValue() + '\n\n';
        
        if (addedHosts.length > 0) {
            workNote += 'NEW HOSTS AFFECTED (' + addedHosts.length + '):\n';
            workNote += this._sysIdsToHostnames(addedHosts) + '\n\n';
        }
        
        if (removedHosts.length > 0) {
            workNote += 'REMEDIATED HOSTS (' + removedHosts.length + '):\n';
            workNote += this._sysIdsToHostnames(removedHosts) + '\n\n';
        }
        
        if (addedHosts.length === 0 && removedHosts.length === 0) {
            workNote += 'No changes to CMDB-linked hosts.\n\n';
        }
        
        workNote += 'Current Status:\n';
        workNote += '- Total hosts affected: ' + vulnGroup.hosts.length + '\n';
        workNote += '- CMDB-linked: ' + currentHostProcessing.matchedSysIds.length + '\n';
        workNote += '- Not in CMDB: ' + currentHostProcessing.unmatchedHosts.length + '\n';
        
        // Update RITM
        ritmGr.work_notes = workNote;
        
        // Update impacted_system variable
        if (currentHostProcessing.matchedSysIds.length > 0) {
            ritmGr.variables.impacted_system = currentHostProcessing.matchedSysIds.join(',');
        }
        
        // Update justification with current host list
        var justification = this._buildJustification(vulnGroup.qid, vulnGroup, vulnDetails, currentHostProcessing);
        ritmGr.variables.justification_for_exception = justification;
        
        ritmGr.update();
        
        this.log.info('Updated RITM: ' + ritmGr.number + ' | Added: ' + addedHosts.length + ' | Removed: ' + removedHosts.length);
    },
    
    /**
     * Flag RITM for closure when all hosts are remediated
     * @param {GlideRecord} ritmGr - RITM record
     * @param {string} qid - QID
     */
    _flagRITMForClosure: function(ritmGr, qid) {
        this.log.info('Flagging RITM for closure: ' + ritmGr.number + ' (QID: ' + qid + ')');
        
        var workNote = '╔══════════════════════════════════════════════════════════════╗\n';
        workNote += '║         ALL HOSTS REMEDIATED - REVIEW FOR CLOSURE            ║\n';
        workNote += '╚══════════════════════════════════════════════════════════════╝\n\n';
        workNote += 'Date: ' + new GlideDateTime().getDisplayValue() + '\n\n';
        workNote += 'The Qualys integration has detected that ALL hosts previously\n';
        workNote += 'affected by this vulnerability (QID: ' + qid + ') have been remediated.\n\n';
        workNote += 'Total hosts remediated: ' + this._getPreviousHostCount(ritmGr) + '\n\n';
        workNote += 'ACTION REQUIRED:\n';
        workNote += 'Please review this exception request and close if appropriate.\n';
        
        ritmGr.work_notes = workNote;
        
        // Clear impacted systems since all are remediated
        ritmGr.variables.impacted_system = '';
        
        ritmGr.update();
    },
    
    /**
     * Get previous host count from RITM
     */
    _getPreviousHostCount: function(ritmGr) {
        var prevHostSysIds = ritmGr.variables.impacted_system ? ritmGr.variables.impacted_system.toString() : '';
        if (!prevHostSysIds) return 0;
        return prevHostSysIds.split(',').filter(function(s) { return s; }).length;
    },
    
    // ============================================================
    // HOST PROCESSING METHODS
    // ============================================================
    
    /**
     * Process hosts - lookup in CMDB and separate matched from unmatched
     * @param {Array} hosts - Array of host objects
     * @returns {Object} { matchedSysIds: [], matchedHosts: [], unmatchedHosts: [] }
     */
    _processHosts: function(hosts) {
        var result = {
            matchedSysIds: [],
            matchedHosts: [],
            unmatchedHosts: []
        };
        
        for (var i = 0; i < hosts.length; i++) {
            var host = hosts[i];
            var sysId = this._findCISysId(host);
            
            if (sysId) {
                result.matchedSysIds.push(sysId);
                result.matchedHosts.push(host);
            } else {
                result.unmatchedHosts.push(host);
            }
        }
        
        return result;
    },
    
    /**
     * Find CMDB CI sys_id for a host
     * @param {Object} host - Host object with ip, dns, hostname, etc.
     * @returns {string|null} sys_id or null
     */
    _findCISysId: function(host) {
        var gr = new GlideRecord('cmdb_ci');
        
        // Try to match by IP address first (most reliable)
        if (host.ip) {
            gr.initialize();
            gr.addQuery('ip_address', host.ip);
            gr.setLimit(1);
            gr.query();
            if (gr.next()) {
                return gr.sys_id.toString();
            }
        }
        
        // Try to match by exact hostname
        var hostname = host.hostname || host.dns || '';
        if (hostname) {
            var shortName = hostname.split('.')[0].toUpperCase();
            
            gr.initialize();
            gr.addQuery('name', shortName);
            gr.setLimit(1);
            gr.query();
            if (gr.next()) {
                return gr.sys_id.toString();
            }
            
            // Try case-insensitive
            gr.initialize();
            gr.addQuery('name', 'STARTSWITH', shortName);
            gr.setLimit(1);
            gr.query();
            if (gr.next()) {
                return gr.sys_id.toString();
            }
        }
        
        return null;
    },
    
    /**
     * Convert sys_ids to hostnames for display
     * @param {Array} sysIds - Array of CI sys_ids
     * @returns {string} Formatted hostname list
     */
    _sysIdsToHostnames: function(sysIds) {
        var names = [];
        
        for (var i = 0; i < sysIds.length; i++) {
            var gr = new GlideRecord('cmdb_ci');
            if (gr.get(sysIds[i])) {
                names.push('  - ' + gr.name + ' (' + gr.ip_address + ')');
            } else {
                names.push('  - [Unknown CI] (' + sysIds[i] + ')');
            }
        }
        
        return names.join('\n');
    },
    
    // ============================================================
    // CONTENT BUILDING METHODS
    // ============================================================
    
    /**
     * Build justification text for RITM - includes ALL hosts
     * @param {string} qid - Qualys QID
     * @param {Object} vulnGroup - Vulnerability group data
     * @param {Object} vulnDetails - KB details
     * @param {Object} hostProcessing - Processed host data
     * @returns {string} Justification text
     */
    _buildJustification: function(qid, vulnGroup, vulnDetails, hostProcessing) {
        var text = 'Auto-generated Exception Request from Qualys Integration\n';
        text += '═══════════════════════════════════════════════════════════\n\n';
        
        text += 'VULNERABILITY DETAILS\n';
        text += '─────────────────────\n';
        text += 'QID: ' + qid + '\n';
        
        if (vulnDetails) {
            text += 'Title: ' + (vulnDetails.title || 'N/A') + '\n';
            text += 'CVSS v3: ' + (vulnDetails.cvss3Base || 'N/A') + '\n';
            text += 'CVSS v2: ' + (vulnDetails.cvssBase || 'N/A') + '\n';
            
            if (vulnDetails.cveList && vulnDetails.cveList.length > 0) {
                text += 'CVEs: ' + vulnDetails.cveList.join(', ') + '\n';
            }
        }
        
        text += 'Severity: ' + vulnGroup.severity + '\n';
        text += '\n';
        
        // Host summary
        text += 'AFFECTED HOSTS SUMMARY\n';
        text += '──────────────────────\n';
        text += 'Total Hosts: ' + vulnGroup.hosts.length + '\n';
        text += 'CMDB-Linked: ' + hostProcessing.matchedHosts.length + '\n';
        text += 'Not in CMDB: ' + hostProcessing.unmatchedHosts.length + '\n';
        text += '\n';
        
        // CMDB-linked hosts
        if (hostProcessing.matchedHosts.length > 0) {
            text += 'CMDB-LINKED HOSTS (' + hostProcessing.matchedHosts.length + ')\n';
            text += '─────────────────────────────────────────\n';
            for (var i = 0; i < hostProcessing.matchedHosts.length; i++) {
                var h = hostProcessing.matchedHosts[i];
                text += '  • ' + (h.hostname || h.dns || 'Unknown') + ' (' + h.ip + ')\n';
            }
            text += '\n';
        }
        
        // Unmatched hosts
        if (hostProcessing.unmatchedHosts.length > 0) {
            text += '*** HOSTS NOT IN CMDB (' + hostProcessing.unmatchedHosts.length + ') ***\n';
            text += '─────────────────────────────────────────\n';
            for (var j = 0; j < hostProcessing.unmatchedHosts.length; j++) {
                var uh = hostProcessing.unmatchedHosts[j];
                text += '  • ' + (uh.hostname || uh.dns || 'Unknown') + ' (' + uh.ip + ') - NOT IN CMDB\n';
            }
            text += '\nNote: These hosts should be added to CMDB for proper tracking.\n';
            text += '\n';
        }
        
        // Solution if available
        if (vulnDetails && vulnDetails.solution) {
            text += 'RECOMMENDED SOLUTION\n';
            text += '────────────────────\n';
            text += vulnDetails.solution.substring(0, 1000) + '\n';
        }
        
        return text;
    },
    
    // ============================================================
    // UTILITY METHODS
    // ============================================================
    
    /**
     * Extract tag value using regex
     * @param {string} xml - XML string
     * @param {string} tagName - Tag to extract
     * @returns {string} Tag value
     */
    _extractTag: function(xml, tagName) {
        var regex = new RegExp('<' + tagName + '>([\\s\\S]*?)</' + tagName + '>', 'i');
        var match = regex.exec(xml);
        return match ? match[1].trim() : '';
    },
    
    /**
     * Extract nested tag value
     * @param {string} xml - XML string
     * @param {string} parentTag - Parent tag
     * @param {string} childTag - Child tag
     * @returns {string} Tag value
     */
    _extractTagPath: function(xml, parentTag, childTag) {
        var parentRegex = new RegExp('<' + parentTag + '>([\\s\\S]*?)</' + parentTag + '>', 'i');
        var parentMatch = parentRegex.exec(xml);
        if (parentMatch) {
            return this._extractTag(parentMatch[1], childTag);
        }
        return '';
    },
    
    /**
     * Clean CDATA wrapper from string
     * @param {string} value - String possibly containing CDATA
     * @returns {string} Cleaned string
     */
    _cleanCDATA: function(value) {
        if (!value) return '';
        return value.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1').trim();
    },
    
    type: 'QualysExceptionIntegration'
};
