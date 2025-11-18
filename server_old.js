const express = require('express');
const { connect, signers } = require('@hyperledger/fabric-gateway');
const grpc = require('@grpc/grpc-js');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(express.json());

// Load configuration
const config = require('./config.json');

// Helper to read files safely
function resolvePath(relativePath) {
    return path.resolve(__dirname, config.networkRoot, relativePath);
}

// 1. CREATE GRPC CLIENT (Replaces Connection Profile)
async function createGrpcClient() {
    // Define path to the Peer's TLS Certificate
    const tlsCertPath = resolvePath(
        'organizations/peerOrganizations/veridat.example.com/peers/peer0.veridat.example.com/tls/ca.crt'
    );

    if (!fs.existsSync(tlsCertPath)) {
        throw new Error(`TLS Root Certificate not found at: ${tlsCertPath}`);
    }

    const tlsRootCert = fs.readFileSync(tlsCertPath);
    
    // Define the Peer Endpoint (Host:Port)
    // Note: grpc-js wants "host:port", NOT "grpcs://host:port"
    const peerEndpoint = 'localhost:7056'; 
    const hostAlias = 'peer0.veridat.example.com'; // Matches the certificate CN

    console.log(`🔌 Creating gRPC client to ${peerEndpoint} (override: ${hostAlias})`);

    return new grpc.Client(
        peerEndpoint,
        grpc.credentials.createSsl(tlsRootCert),
        {
            'grpc.ssl_target_name_override': hostAlias,
        }
    );
}

// 2. LOAD IDENTITY (Replaces buildWallet)
async function loadIdentity() {
    // Try User1 first, then fallback to Admin
    let userBaseDir = resolvePath('organizations/peerOrganizations/veridat.example.com/users/User1@veridat.example.com');
    
    if (!fs.existsSync(userBaseDir)) {
        console.log('⚠️  User1 not found, trying Admin...');
        userBaseDir = resolvePath('organizations/peerOrganizations/veridat.example.com/users/Admin@veridat.example.com');
    }

    if (!fs.existsSync(userBaseDir)) {
        throw new Error(`No user credentials found at ${userBaseDir}`);
    }

    // Find Certificate (.pem)
    const certDir = path.join(userBaseDir, 'msp/signcerts');
    const certFiles = fs.readdirSync(certDir).filter(f => f.endsWith('.pem'));
    if (certFiles.length === 0) throw new Error(`No .pem file found in ${certDir}`);
    const certPath = path.join(certDir, certFiles[0]);
    const certificate = fs.readFileSync(certPath);

    // Find Private Key (in keystore)
    const keyDir = path.join(userBaseDir, 'msp/keystore');
    const keyFiles = fs.readdirSync(keyDir);
    if (keyFiles.length === 0) throw new Error(`No key found in ${keyDir}`);
    const keyPath = path.join(keyDir, keyFiles[0]);
    const privateKeyPem = fs.readFileSync(keyPath);
    const privateKey = crypto.createPrivateKey(privateKeyPem);

    console.log(`👤 Loaded Identity: ${config.mspId} (${certFiles[0]})`);

    return {
        mspId: config.mspId,
        credentials: certificate,
        privateKey: privateKey
    };
}

// 3. CONNECT TO NETWORK
async function connectToNetwork() {
    try {
        const client = await createGrpcClient();
        const identity = await loadIdentity();

        // Connect to the Gateway
        const gateway = connect({
            client,
            identity: {
                mspId: identity.mspId,
                credentials: identity.credentials,
            },
            signer: signers.newPrivateKeySigner(identity.privateKey),
            // Default options for transactions
            evaluateOptions: () => {
                return { deadline: Date.now() + 5000 }; // 5 seconds timeout for queries
            },
            endorseOptions: () => {
                return { deadline: Date.now() + 15000 }; // 15 seconds timeout for invokes
            },
        });

        console.log('✅ Gateway connected');

        const network = gateway.getNetwork(config.channelName);
        const contract = network.getContract(config.chaincodeName);

        return { gateway, client, contract };
    } catch (error) {
        console.error('❌ Connection failed:', error);
        throw error;
    }
}

// ===== ROUTES =====

// Get all hashes
app.get('/api/hashes', async (req, res) => {
    let gateway;
    let client;
    try {
        console.log('📊 Querying all hashes...');
        const connection = await connectToNetwork();
        gateway = connection.gateway;
        client = connection.client;
        const contract = connection.contract;

        // NOTE: New SDK returns Uint8Array, simpler than the old Buffer handling
        const resultBytes = await contract.evaluateTransaction('GetAllHashes');
        const resultString = new TextDecoder().decode(resultBytes);
        
        console.log('📦 Raw result:', resultString);
        const data = JSON.parse(resultString);

        res.json({
            success: true,
            count: data.data ? data.data.length : 0,
            data: data.data || [],
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error(`❌ Query failed: ${error.message}`);
        res.status(500).json({ success: false, error: error.message });
    } finally {
        // Clean up resources
        if (gateway) gateway.close();
        if (client) client.close();
    }
});

// Get hash by document ID
app.get('/api/hash/:documentId', async (req, res) => {
    let gateway;
    let client;
    try {
        const { documentId } = req.params;
        console.log(`🔍 Querying document: ${documentId}`);
        
        const connection = await connectToNetwork();
        gateway = connection.gateway;
        client = connection.client;
        const contract = connection.contract;

        const resultBytes = await contract.evaluateTransaction('GetAllHashes');
        const resultString = new TextDecoder().decode(resultBytes);
        const data = JSON.parse(resultString);

        if (data.status === 'success' && data.data) {
            const found = data.data.find(item => item.documentID === documentId);
            if (found) {
                res.json({
                    success: true,
                    data: found,
                    shareLink: `${req.protocol}://${req.get('host')}/api/hash/${documentId}`
                });
            } else {
                res.status(404).json({ success: false, message: `Document ID '${documentId}' not found` });
            }
        } else {
            res.status(404).json({ success: false, message: 'No data available' });
        }
    } catch (error) {
        console.error(`❌ Query failed: ${error.message}`);
        res.status(500).json({ success: false, error: error.message });
    } finally {
        if (gateway) gateway.close();
        if (client) client.close();
    }
});

// Search by hash value
app.get('/api/search/:hashValue', async (req, res) => {
    let gateway;
    let client;
    try {
        const { hashValue } = req.params;
        
        const connection = await connectToNetwork();
        gateway = connection.gateway;
        client = connection.client;
        const contract = connection.contract;

        const resultBytes = await contract.evaluateTransaction('GetAllHashes');
        const resultString = new TextDecoder().decode(resultBytes);
        const data = JSON.parse(resultString);

        if (data.status === 'success' && data.data) {
            const found = data.data.find(item => item.hash === hashValue);
            if (found) {
                res.json({ success: true, data: found });
            } else {
                res.status(404).json({ success: false, message: 'Hash not found' });
            }
        } else {
            res.status(404).json({ success: false, message: 'No data available' });
        }
    } catch (error) {
        console.error(`❌ Query failed: ${error.message}`);
        res.status(500).json({ success: false, error: error.message });
    } finally {
        if (gateway) gateway.close();
        if (client) client.close();
    }
});

// Health check
app.get('/health', (req, res) => {
    res.json({ 
        status: 'healthy', 
        sdk: '@hyperledger/fabric-gateway',
        timestamp: new Date().toISOString(),
        channel: config.channelName
    });
});

// Web Interface (Unchanged from your version)
app.get('/', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Veridat Hash Explorer</title>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body { font-family: sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; background: #f5f7fa; }
                .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; }
                .search-box { margin: 30px 0; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
                input { padding: 12px; width: 400px; font-size: 16px; }
                button { padding: 12px 24px; background: #667eea; color: white; border: none; cursor: pointer; margin-left: 10px; border-radius: 5px;}
                .result { background: white; padding: 20px; margin: 15px 0; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
                .hash { font-family: monospace; background: #f8f9fa; padding: 10px; word-break: break-all; }
            </style>
        </head>
        <body>
            <div class="header"><h1>🔍 Veridat Hash Explorer</h1></div>
            <div class="search-box">
                <input type="text" id="searchInput" placeholder="Enter document ID or hash value">
                <button onclick="search()">🔍 Search</button>
                <button onclick="loadAll()">📋 Load All</button>
            </div>
            <div id="results"></div>
            <script>
                async function loadAll() {
                    document.getElementById('results').innerHTML = 'Loading...';
                    const res = await fetch('/api/hashes');
                    const data = await res.json();
                    display(data.data);
                }
                async function search() {
                    const q = document.getElementById('searchInput').value;
                    if(!q) return loadAll();
                    let res = await fetch('/api/hash/'+encodeURIComponent(q));
                    if(!res.ok) res = await fetch('/api/search/'+encodeURIComponent(q));
                    if(res.ok) {
                        const data = await res.json();
                        display([data.data]);
                    } else {
                        document.getElementById('results').innerHTML = 'Not found';
                    }
                }
                function display(items) {
                    if(!items || !items.length) { document.getElementById('results').innerHTML = 'No results'; return; }
                    document.getElementById('results').innerHTML = items.map(i => 
                        \`<div class="result"><b>ID:</b> \${i.documentID}<br><b>Hash:</b> <div class="hash">\${i.hash}</div></div>\`
                    ).join('');
                }
                window.onload = loadAll;
            </script>
        </body>
        </html>
    `);
});

const PORT = config.port || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Veridat Explorer API running on port ${PORT}`);
    console.log(`🔥 Using @hyperledger/fabric-gateway SDK`);
    console.log(`📍 Web Interface:  http://localhost:${PORT}`);
    console.log(`📍 API Endpoint:   http://localhost:${PORT}/api/hashes`);
    console.log(`📍 Health Check:   http://localhost:${PORT}/health`);
});