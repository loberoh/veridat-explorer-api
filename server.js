const express = require('express');
const { Gateway, Wallets } = require('fabric-network');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(express.json());

// Load configuration
const config = require('./config.json');

// Build connection profile
function buildConnectionProfile() {
    const ccpPath = path.resolve(
        __dirname,
        config.networkRoot, 
        'organizations', 
        'peerOrganizations', 
        'veridat.example.com', 
        'connection-veridat.json'
    );
    
    // If connection profile doesn't exist, create it manually
    if (!fs.existsSync(ccpPath)) {
        console.log('⚠️  Connection profile not found, using default configuration');
        
        const tlsCertPath = path.resolve(
            __dirname,
            config.networkRoot,
            'organizations/peerOrganizations/veridat.example.com/peers/peer0.veridat.example.com/tls/ca.crt'
        );
        
        console.log('🔍 Using peer port: 7056');
        
        return {
            name: 'veridat-network',
            version: '1.0.0',
            client: {
                organization: 'Veridat',
                connection: {
                    timeout: {
                        peer: { endorser: '300' },
                        orderer: '300'
                    }
                }
            },
            channels: {
                paralite: {
                    peers: {
                        'peer0.veridat.example.com': {
                            endorsingPeer: true,
                            chaincodeQuery: true,
                            ledgerQuery: true,
                            eventSource: true
                        }
                    }
                }
            },
            organizations: {
                Veridat: {
                    mspid: 'VeridatMSP',
                    peers: ['peer0.veridat.example.com'],
                    certificateAuthorities: ['ca.veridat.example.com']
                }
            },
            peers: {
                'peer0.veridat.example.com': {
                    url: 'grpcs://localhost:7056',
                    tlsCACerts: {
                        pem: fs.readFileSync(tlsCertPath).toString()
                    },
                    grpcOptions: {
                        'ssl-target-name-override': 'peer0.veridat.example.com',
                        'hostnameOverride': 'peer0.veridat.example.com'
                    }
                }
            }
        };
    }
    
    const contents = fs.readFileSync(ccpPath, 'utf8');
    return JSON.parse(contents);
}

// Build wallet with admin identity
async function buildWallet() {
    const walletPath = path.join(__dirname, 'wallet');
    const wallet = await Wallets.newFileSystemWallet(walletPath);

    // Check if identity exists
    const identity = await wallet.get('appUser');
    if (!identity) {
        console.log('📝 Creating appUser identity in wallet...');
        
        // Try User1 first (designed for client apps)
        let credPath = path.resolve(
            __dirname,
            config.networkRoot,
            'organizations/peerOrganizations/veridat.example.com/users/User1@veridat.example.com'
        );
        
        console.log('🔍 Trying User1 credentials at:', credPath);
        
        // If User1 doesn't exist, fall back to Admin
        if (!fs.existsSync(credPath)) {
            console.log('⚠️  User1 not found, trying Admin...');
            credPath = path.resolve(
                __dirname,
                config.networkRoot,
                'organizations/peerOrganizations/veridat.example.com/users/Admin@veridat.example.com'
            );
        }
        
        // Check if path exists
        if (!fs.existsSync(credPath)) {
            throw new Error(`Credentials path not found: ${credPath}`);
        }
        
        // Read certificate - find the .pem file in signcerts directory
        const signcertsPath = path.join(credPath, 'msp/signcerts');
        if (!fs.existsSync(signcertsPath)) {
            throw new Error(`Signcerts directory not found at: ${signcertsPath}`);
        }
        
        const certFiles = fs.readdirSync(signcertsPath).filter(f => f.endsWith('.pem'));
        if (certFiles.length === 0) {
            throw new Error(`No certificate (.pem) found in: ${signcertsPath}`);
        }
        
        const certPath = path.join(signcertsPath, certFiles[0]);
        console.log('✅ Found certificate:', certFiles[0]);
        const certificate = fs.readFileSync(certPath).toString();
        
        // Read private key (find the first key in keystore)
        const keystorePath = path.join(credPath, 'msp/keystore');
        if (!fs.existsSync(keystorePath)) {
            throw new Error(`Keystore directory not found at: ${keystorePath}`);
        }
        
        const keyFiles = fs.readdirSync(keystorePath);
        if (keyFiles.length === 0) {
            throw new Error(`No private key found in: ${keystorePath}`);
        }
        
        console.log('✅ Found private key:', keyFiles[0]);
        const privateKey = fs.readFileSync(path.join(keystorePath, keyFiles[0])).toString();

        // Create X.509 identity
        const x509Identity = {
            credentials: {
                certificate: certificate,
                privateKey: privateKey,
            },
            mspId: config.mspId,
            type: 'X.509',
        };

        await wallet.put('appUser', x509Identity);
        console.log('✅ User identity created successfully in wallet');
    } else {
        console.log('✅ User identity already exists in wallet');
    }

    return wallet;
}

// Create gateway connection (reusable)
async function connectToNetwork() {
    try {
        console.log('🔄 Connecting to Fabric network...');
        const ccp = buildConnectionProfile();
        const wallet = await buildWallet();

        const gateway = new Gateway();
        
        await gateway.connect(ccp, {
            wallet,
            identity: 'appUser',  // ← CHANGED from 'admin' to 'appUser'
            discovery: { enabled: false }
        });

        console.log('✅ Gateway connected');

        const network = await gateway.getNetwork(config.channelName);
        console.log('✅ Network channel obtained:', config.channelName);
        
        const contract = network.getContract(config.chaincodeName);
        console.log('✅ Contract obtained:', config.chaincodeName);

        return { gateway, network, contract };
    } catch (error) {
        console.error('❌ Failed to connect to network:', error.message);
        console.error('Full error:', error);
        throw error;
    }
}

// Get all hashes
app.get('/api/hashes', async (req, res) => {
    let gateway;
    try {
        console.log('📊 Querying all hashes...');
        const connection = await connectToNetwork();
        gateway = connection.gateway;
        const contract = connection.contract;

        console.log('📞 Calling GetAllHashes function...');
        const result = await contract.evaluateTransaction('GetAllHashes');
        console.log('📦 Raw result:', result.toString());
        
        const data = JSON.parse(result.toString());
        console.log('✅ Parsed data:', JSON.stringify(data, null, 2));

        await gateway.disconnect();
        console.log('✅ Query successful');

        res.json({
            success: true,
            count: data.data ? data.data.length : 0,
            data: data.data || [],
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        console.error(`❌ Query failed: ${error.message}`);
        console.error('❌ Error stack:', error.stack);
        console.error('❌ Error details:', JSON.stringify(error, null, 2));
        if (gateway) {
            try {
                await gateway.disconnect();
            } catch (e) {
                // Ignore disconnect errors
            }
        }
        res.status(500).json({
            success: false,
            error: error.message,
            details: error.toString()
        });
    }
});

// ===== API ENDPOINTS =====

// Health check
app.get('/health', (req, res) => {
    res.json({ 
        status: 'healthy', 
        timestamp: new Date().toISOString(),
        network: 'veridat',
        channel: config.channelName,
        chaincode: config.chaincodeName
    });
});

// API documentation
app.get('/api', (req, res) => {
    res.json({
        name: 'Veridat Explorer API',
        version: '1.0.0',
        endpoints: {
            'GET /': 'Web interface',
            'GET /health': 'Health check',
            'GET /api': 'API documentation',
            'GET /api/hashes': 'Get all stored hashes',
            'GET /api/hash/:documentId': 'Get hash by document ID',
            'GET /api/search/:hashValue': 'Search by hash value'
        }
    });
});

// Get all hashes
// app.get('/api/hashes', async (req, res) => {
//     let gateway;
//     try {
//         console.log('📊 Querying all hashes...');
//         const connection = await connectToNetwork();
//         gateway = connection.gateway;
//         const contract = connection.contract;

//         const result = await contract.evaluateTransaction('GetAllHashes');
//         const data = JSON.parse(result.toString());

//         await gateway.disconnect();
//         console.log('✅ Query successful');

//         res.json({
//             success: true,
//             count: data.data ? data.data.length : 0,
//             data: data.data || [],
//             timestamp: new Date().toISOString()
//         });
//     } catch (error) {
//         console.error(`❌ Query failed: ${error.message}`);
//         if (gateway) {
//             try {
//                 await gateway.disconnect();
//             } catch (e) {
//                 // Ignore disconnect errors
//             }
//         }
//         res.status(500).json({
//             success: false,
//             error: error.message
//         });
//     }
// });

// Get hash by document ID
app.get('/api/hash/:documentId', async (req, res) => {
    let gateway;
    try {
        const { documentId } = req.params;
        console.log(`🔍 Querying document: ${documentId}`);
        
        const connection = await connectToNetwork();
        gateway = connection.gateway;
        const contract = connection.contract;

        // Query all hashes and find the specific one
        const result = await contract.evaluateTransaction('GetAllHashes');
        const data = JSON.parse(result.toString());

        await gateway.disconnect();

        if (data.status === 'success' && data.data) {
            const found = data.data.find(item => item.documentID === documentId);
            if (found) {
                console.log('✅ Document found');
                res.json({
                    success: true,
                    data: found,
                    shareLink: `${req.protocol}://${req.get('host')}/api/hash/${documentId}`
                });
            } else {
                console.log('⚠️  Document not found');
                res.status(404).json({
                    success: false,
                    message: `Document ID '${documentId}' not found`
                });
            }
        } else {
            res.status(404).json({
                success: false,
                message: 'No data available'
            });
        }
    } catch (error) {
        console.error(`❌ Query failed: ${error.message}`);
        if (gateway) {
            try {
                await gateway.disconnect();
            } catch (e) {
                // Ignore disconnect errors
            }
        }
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Search by hash value
app.get('/api/search/:hashValue', async (req, res) => {
    let gateway;
    try {
        const { hashValue } = req.params;
        console.log(`🔍 Searching for hash: ${hashValue.substring(0, 20)}...`);
        
        const connection = await connectToNetwork();
        gateway = connection.gateway;
        const contract = connection.contract;

        const result = await contract.evaluateTransaction('GetAllHashes');
        const data = JSON.parse(result.toString());

        await gateway.disconnect();

        if (data.status === 'success' && data.data) {
            const found = data.data.find(item => item.hash === hashValue);
            if (found) {
                console.log('✅ Hash found');
                res.json({
                    success: true,
                    data: found
                });
            } else {
                console.log('⚠️  Hash not found');
                res.status(404).json({
                    success: false,
                    message: 'Hash not found'
                });
            }
        } else {
            res.status(404).json({
                success: false,
                message: 'No data available'
            });
        }
    } catch (error) {
        console.error(`❌ Query failed: ${error.message}`);
        if (gateway) {
            try {
                await gateway.disconnect();
            } catch (e) {
                // Ignore disconnect errors
            }
        }
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Simple web interface
app.get('/', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Veridat Hash Explorer</title>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                * { box-sizing: border-box; }
                body { 
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
                    max-width: 1200px; 
                    margin: 0 auto; 
                    padding: 20px;
                    background: #f5f7fa;
                }
                .header { 
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white; 
                    padding: 30px; 
                    border-radius: 10px;
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                }
                .header h1 { margin: 0 0 10px 0; }
                .header p { margin: 0; opacity: 0.9; }
                .search-box { 
                    margin: 30px 0;
                    background: white;
                    padding: 20px;
                    border-radius: 10px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }
                input { 
                    padding: 12px; 
                    width: 400px; 
                    font-size: 16px;
                    border: 2px solid #e1e8ed;
                    border-radius: 5px;
                }
                input:focus {
                    outline: none;
                    border-color: #667eea;
                }
                button { 
                    padding: 12px 24px; 
                    font-size: 16px; 
                    background: #667eea;
                    color: white; 
                    border: none;
                    border-radius: 5px;
                    cursor: pointer;
                    margin-left: 10px;
                    transition: background 0.3s;
                }
                button:hover { background: #5568d3; }
                button:disabled {
                    background: #ccc;
                    cursor: not-allowed;
                }
                .stats {
                    background: white;
                    padding: 20px;
                    border-radius: 10px;
                    margin-bottom: 20px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }
                .result { 
                    background: white;
                    padding: 20px; 
                    margin: 15px 0; 
                    border-radius: 10px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    transition: transform 0.2s;
                }
                .result:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 4px 8px rgba(0,0,0,0.15);
                }
                .hash { 
                    font-family: 'Courier New', monospace;
                    word-break: break-all;
                    background: #f8f9fa;
                    padding: 10px;
                    border-radius: 5px;
                    margin: 10px 0;
                    font-size: 14px;
                }
                .label { 
                    font-weight: 600;
                    color: #667eea;
                    display: inline-block;
                    width: 120px;
                }
                .loading {
                    text-align: center;
                    padding: 40px;
                    color: #667eea;
                    font-size: 18px;
                }
                .error {
                    background: #fee;
                    color: #c33;
                    padding: 20px;
                    border-radius: 10px;
                    margin: 20px 0;
                }
                a {
                    color: #667eea;
                    text-decoration: none;
                }
                a:hover {
                    text-decoration: underline;
                }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🔍 Veridat Hash Explorer</h1>
                <p>Query stored document hashes on the blockchain</p>
            </div>
            
            <div class="search-box">
                <input type="text" id="searchInput" placeholder="Enter document ID or hash value" onkeypress="handleKeyPress(event)">
                <button onclick="search()" id="searchBtn">🔍 Search</button>
                <button onclick="loadAll()" id="loadAllBtn">📋 Load All</button>
            </div>
            
            <div class="stats" id="stats" style="display:none;">
                <strong>Total Records:</strong> <span id="totalRecords">0</span>
            </div>
            
            <div id="results"></div>
            
            <script>
                let isLoading = false;

                function handleKeyPress(event) {
                    if (event.key === 'Enter') {
                        search();
                    }
                }

                function setLoading(loading) {
                    isLoading = loading;
                    document.getElementById('searchBtn').disabled = loading;
                    document.getElementById('loadAllBtn').disabled = loading;
                }

                async function search() {
                    if (isLoading) return;
                    
                    const query = document.getElementById('searchInput').value.trim();
                    if (!query) { 
                        loadAll(); 
                        return; 
                    }
                    
                    showLoading('Searching...');
                    setLoading(true);
                    
                    try {
                        // Try as document ID first
                        let response = await fetch(\`/api/hash/\${encodeURIComponent(query)}\`);
                        if (response.ok) {
                            const data = await response.json();
                            displayResults([data.data]);
                            setLoading(false);
                            return;
                        }
                        
                        // Try as hash value
                        response = await fetch(\`/api/search/\${encodeURIComponent(query)}\`);
                        if (response.ok) {
                            const data = await response.json();
                            displayResults([data.data]);
                        } else {
                            document.getElementById('results').innerHTML = 
                                '<div class="result">❌ No results found for: ' + escapeHtml(query) + '</div>';
                        }
                    } catch (error) {
                        document.getElementById('results').innerHTML = 
                            '<div class="error">❌ Error: ' + escapeHtml(error.message) + '</div>';
                    } finally {
                        setLoading(false);
                    }
                }

                async function loadAll() {
                    if (isLoading) return;
                    
                    showLoading('Loading all hashes from blockchain...');
                    setLoading(true);
                    
                    try {
                        const response = await fetch('/api/hashes');
                        if (!response.ok) {
                            throw new Error('Failed to fetch hashes: ' + response.statusText);
                        }
                        
                        const data = await response.json();
                        
                        if (data.success) {
                            document.getElementById('stats').style.display = 'block';
                            document.getElementById('totalRecords').textContent = data.count;
                            displayResults(data.data);
                        } else {
                            throw new Error(data.error || 'Unknown error');
                        }
                    } catch (error) {
                        document.getElementById('results').innerHTML = 
                            '<div class="error">❌ Error: ' + escapeHtml(error.message) + 
                            '<br><br>Make sure your Fabric network is running!</div>';
                    } finally {
                        setLoading(false);
                    }
                }

                function showLoading(message) {
                    document.getElementById('results').innerHTML = 
                        '<div class="loading">⏳ ' + escapeHtml(message || 'Loading...') + '</div>';
                }

                function displayResults(items) {
                    if (!items || items.length === 0) {
                        document.getElementById('results').innerHTML = 
                            '<div class="result">No results found</div>';
                        return;
                    }
                    
                    const html = items.map(item => \`
                        <div class="result">
                            <div><span class="label">Document ID:</span> <strong>\${escapeHtml(item.documentID)}</strong></div>
                            <div><span class="label">Timestamp:</span> \${escapeHtml(item.timestamp)}</div>
                            <div><span class="label">Hash:</span></div>
                            <div class="hash">\${escapeHtml(item.hash)}</div>
                            <div><span class="label">Share Link:</span> 
                                <a href="/api/hash/\${encodeURIComponent(item.documentID)}" target="_blank">
                                    \${window.location.origin}/api/hash/\${encodeURIComponent(item.documentID)}
                                </a>
                            </div>
                        </div>
                    \`).join('');
                    
                    document.getElementById('results').innerHTML = html;
                }

                function escapeHtml(text) {
                    const div = document.createElement('div');
                    div.textContent = text;
                    return div.innerHTML;
                }

                // Load all on page load
                window.onload = () => {
                    console.log('Veridat Explorer loaded');
                    loadAll();
                };
            </script>
        </body>
        </html>
    `);
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({
        success: false,
        error: err.message || 'Internal server error'
    });
});

// Start server
const PORT = config.port || 3000;
const server = app.listen(PORT, () => {
    console.log('='.repeat(50));
    console.log('🚀 Veridat Explorer API Server Started!');
    console.log('='.repeat(50));
    console.log(`📍 Web Interface:  http://localhost:${PORT}`);
    console.log(`📍 API Endpoint:   http://localhost:${PORT}/api/hashes`);
    console.log(`📍 Health Check:   http://localhost:${PORT}/health`);
    console.log('='.repeat(50));
    console.log(`🔗 Channel:        ${config.channelName}`);
    console.log(`🔗 Chaincode:      ${config.chaincodeName}`);
    console.log('='.repeat(50));
    console.log('💡 Tip: Make sure your Fabric network is running!');
    console.log('='.repeat(50));
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM received, shutting down gracefully...');
    server.close(() => {
        console.log('Server closed');
        process.exit(0);
    });
});

process.on('SIGINT', () => {
    console.log('\nSIGINT received, shutting down gracefully...');
    server.close(() => {
        console.log('Server closed');
        process.exit(0);
    });
});