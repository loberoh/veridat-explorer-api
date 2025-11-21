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
    const tlsCertPath = resolvePath(
        'organizations/peerOrganizations/veridat.example.com/peers/peer0.veridat.example.com/tls/ca.crt'
    );

    if (!fs.existsSync(tlsCertPath)) {
        throw new Error(`TLS Root Certificate not found at: ${tlsCertPath}`);
    }

    const tlsRootCert = fs.readFileSync(tlsCertPath);
    const peerEndpoint = 'localhost:7056'; 
    const hostAlias = 'peer0.veridat.example.com';

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
    let userBaseDir = resolvePath('organizations/peerOrganizations/veridat.example.com/users/User1@veridat.example.com');
    
    if (!fs.existsSync(userBaseDir)) {
        console.log('⚠️  User1 not found, trying Admin...');
        userBaseDir = resolvePath('organizations/peerOrganizations/veridat.example.com/users/Admin@veridat.example.com');
    }

    if (!fs.existsSync(userBaseDir)) {
        throw new Error(`No user credentials found at ${userBaseDir}`);
    }

    const certDir = path.join(userBaseDir, 'msp/signcerts');
    const certFiles = fs.readdirSync(certDir).filter(f => f.endsWith('.pem'));
    if (certFiles.length === 0) throw new Error(`No .pem file found in ${certDir}`);
    const certPath = path.join(certDir, certFiles[0]);
    const certificate = fs.readFileSync(certPath);

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

        const gateway = connect({
            client,
            identity: {
                mspId: identity.mspId,
                credentials: identity.credentials,
            },
            signer: signers.newPrivateKeySigner(identity.privateKey),
            evaluateOptions: () => {
                return { deadline: Date.now() + 5000 };
            },
            endorseOptions: () => {
                return { deadline: Date.now() + 15000 };
            },
        });

        console.log('✅ Gateway connected');

        const network = gateway.getNetwork(config.channelName);
        const contract = network.getContract(config.chaincodeName);

        return { gateway, client, contract, network };
    } catch (error) {
        console.error('❌ Connection failed:', error);
        throw error;
    }
}

// 4. MANUAL PROTOBUF PARSING (NO LIBRARY NEEDED!)

// Decode varint (variable-length integer) from buffer
function decodeVarint(buffer, offset) {
    let result = 0;
    let shift = 0;
    let byte;
    let pos = offset;
    
    do {
        if (pos >= buffer.length) {
            throw new Error('Varint extends beyond buffer');
        }
        byte = buffer[pos++];
        result |= (byte & 0x7f) << shift;
        shift += 7;
    } while (byte & 0x80);
    
    return { value: result, bytesRead: pos - offset };
}

// Enhanced: Parse multiple fields from block
function parseBlockData(blockBytes) {
    try {
        let pos = 0;
        const result = {
            blockNumber: null,
            previousHash: null,
            dataHash: null,
            transactionCount: 0
        };
        
        // Field 1: Header (0x0a = field 1, wire type 2 - length-delimited)
        if (blockBytes[pos] !== 0x0a) {
            throw new Error('Expected header field');
        }
        pos++;
        
        const headerLength = decodeVarint(blockBytes, pos);
        pos += headerLength.bytesRead;
        const headerStart = pos;
        const headerEnd = pos + headerLength.value;
        
        // Parse header contents
        while (pos < headerEnd) {
            const fieldTag = blockBytes[pos];
            
            if (fieldTag === 0x08) {
                // Field 1: Block number (varint)
                pos++;
                const blockNum = decodeVarint(blockBytes, pos);
                result.blockNumber = blockNum.value;
                pos += blockNum.bytesRead;
            } else if (fieldTag === 0x12) {
                // Field 2: Previous hash (length-delimited)
                pos++;
                const hashLen = decodeVarint(blockBytes, pos);
                pos += hashLen.bytesRead;
                result.previousHash = Buffer.from(blockBytes.slice(pos, pos + hashLen.value)).toString('hex');
                pos += hashLen.value;
            } else if (fieldTag === 0x1a) {
                // Field 3: Data hash (length-delimited)
                pos++;
                const hashLen = decodeVarint(blockBytes, pos);
                pos += hashLen.bytesRead;
                result.dataHash = Buffer.from(blockBytes.slice(pos, pos + hashLen.value)).toString('hex');
                pos += hashLen.value;
            } else {
                // Unknown field, skip
                pos++;
            }
        }
        
        // Field 2: Data (0x12 = field 2, wire type 2)
        pos = headerEnd;
        if (pos < blockBytes.length && blockBytes[pos] === 0x12) {
            pos++;
            const dataLength = decodeVarint(blockBytes, pos);
            pos += dataLength.bytesRead;
            
            // Count transactions (each transaction is a length-delimited field)
            const dataEnd = pos + dataLength.value;
            let txCount = 0;
            while (pos < dataEnd) {
                if (blockBytes[pos] === 0x0a) { // Transaction field
                    txCount++;
                    pos++;
                    const txLen = decodeVarint(blockBytes, pos);
                    pos += txLen.bytesRead + txLen.value;
                } else {
                    break;
                }
            }
            result.transactionCount = txCount;
        }
        
        return result;
        
    } catch (error) {
        console.error('Error parsing block data:', error.message);
        return {
            blockNumber: null,
            previousHash: null,
            dataHash: null,
            transactionCount: 0,
            error: error.message
        };
    }
}

// 5. GET BLOCK INFO FROM TRANSACTION ID
async function getBlockInfoFromTxId(network, txId) {
    try {
        console.log(`📦 Querying block for transaction: ${txId}`);
        const qscc = network.getContract('qscc');
        
        const blockBytes = await qscc.evaluateTransaction(
            'GetBlockByTxID',
            config.channelName,
            txId
        );
        
        // Parse comprehensive block data
        const blockData = parseBlockData(blockBytes);
        
        return {
            success: true,
            transactionId: txId,
            blockNumber: blockData.blockNumber,
            previousBlockHash: blockData.previousHash,
            dataHash: blockData.dataHash,
            transactionCount: blockData.transactionCount,
            blockSize: blockBytes.length,
            channel: config.channelName
        };
        
    } catch (error) {
        console.error(`❌ Could not fetch block: ${error.message}`);
        return { 
            success: false, 
            error: error.message 
        };
    }
}

// 6. GET BLOCKCHAIN INFO
async function getChainInfo(network) {
    try {
        const qscc = network.getContract('qscc');
        
        const infoBytes = await qscc.evaluateTransaction(
            'GetChainInfo',
            config.channelName
        );
        
        return {
            success: true,
            channel: config.channelName,
            dataSize: infoBytes.length,
            infoHex: Buffer.from(infoBytes.slice(0, 32)).toString('hex')
        };
        
    } catch (error) {
        console.error(`❌ Could not fetch chain info: ${error.message}`);
        return { success: false, error: error.message };
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
        if (gateway) gateway.close();
        if (client) client.close();
    }
});

// Get hash by document ID WITH BLOCK INFO
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
        const network = connection.network;

        const resultBytes = await contract.evaluateTransaction('GetAllHashes');
        const resultString = new TextDecoder().decode(resultBytes);
        const data = JSON.parse(resultString);

        if (data.status === 'success' && data.data) {
            const found = data.data.find(item => item.documentID === documentId);
            if (found) {
                // Get block info if transaction ID exists
                let blockInfo = null;
                if (found.txId) {
                    console.log(`🔗 Fetching block info for txId: ${found.txId}`);
                    blockInfo = await getBlockInfoFromTxId(network, found.txId);
                }
                
                res.json({
                    success: true,
                    data: found,
                    blockInfo: blockInfo,
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

// Get blockchain info endpoint
app.get('/api/blockchain/info', async (req, res) => {
    let gateway;
    let client;
    try {
        console.log('ℹ️  Querying blockchain info...');
        
        const connection = await connectToNetwork();
        gateway = connection.gateway;
        client = connection.client;
        const network = connection.network;

        const chainInfo = await getChainInfo(network);
        
        res.json(chainInfo);
        
    } catch (error) {
        console.error(`❌ Query failed: ${error.message}`);
        res.status(500).json({ success: false, error: error.message });
    } finally {
        if (gateway) gateway.close();
        if (client) client.close();
    }
});

// Get block info directly by transaction ID (API endpoint - returns JSON)
app.get('/api/block/txid/:txId', async (req, res) => {
    let gateway;
    let client;
    try {
        const { txId } = req.params;
        console.log(`📦 Querying block for transaction: ${txId}`);
        
        const connection = await connectToNetwork();
        gateway = connection.gateway;
        client = connection.client;
        const network = connection.network;

        const blockInfo = await getBlockInfoFromTxId(network, txId);
        
        res.json(blockInfo);
        
    } catch (error) {
        console.error(`❌ Query failed: ${error.message}`);
        res.status(500).json({ success: false, error: error.message });
    } finally {
        if (gateway) gateway.close();
        if (client) client.close();
    }
});

// ===== NEW TRANSACTION EXPLORER ENDPOINTS =====

// API endpoint - Get transaction details by TX ID
app.get('/api/transaction/:txId', async (req, res) => {
    let gateway;
    let client;
    try {
        const { txId } = req.params;
        console.log(`🔍 Querying transaction details for: ${txId}`);
        
        const connection = await connectToNetwork();
        gateway = connection.gateway;
        client = connection.client;
        const contract = connection.contract;
        const network = connection.network;

        // 1. Find the document with this txId
        const resultBytes = await contract.evaluateTransaction('GetAllHashes');
        const resultString = new TextDecoder().decode(resultBytes);
        const data = JSON.parse(resultString);

        if (!data.data) {
            return res.status(404).json({ 
                success: false, 
                error: 'No data available' 
            });
        }

        const transaction = data.data.find(item => item.txId === txId);
        
        if (!transaction) {
            return res.status(404).json({ 
                success: false, 
                error: 'Transaction ID not found in chaincode state' 
            });
        }

        // 2. Get block info
        const blockInfo = await getBlockInfoFromTxId(network, txId);

        // 3. Combine both
        res.json({
            success: true,
            transaction: {
                documentId: transaction.documentID,
                dataHash: transaction.hash,  // YOUR submitted hash
                txId: transaction.txId,
                timestamp: transaction.timestamp
            },
            blockInfo: blockInfo.success ? blockInfo : null
        });

    } catch (error) {
        console.error(`❌ Query failed: ${error.message}`);
        res.status(500).json({ success: false, error: error.message });
    } finally {
        if (gateway) gateway.close();
        if (client) client.close();
    }
});

// HTML Transaction Explorer Page - Pretty display
app.get('/transaction/:txId', (req, res) => {
    const { txId } = req.params;
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Transaction Explorer - ${txId}</title>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body { 
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; 
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
                    margin-bottom: 30px; 
                }
                .back-link { 
                    color: white; 
                    text-decoration: none; 
                    display: inline-block; 
                    margin-top: 10px; 
                    opacity: 0.9; 
                }
                .back-link:hover { opacity: 1; text-decoration: underline; }
                
                /* Main Data Hash Section */
                .data-hash-section {
                    background: white;
                    padding: 40px;
                    border-radius: 10px;
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                    margin-bottom: 30px;
                    text-align: center;
                }
                .data-hash-title {
                    font-size: 14px;
                    text-transform: uppercase;
                    letter-spacing: 2px;
                    color: #667eea;
                    font-weight: bold;
                    margin-bottom: 20px;
                }
                .data-hash-value {
                    font-family: 'Courier New', monospace;
                    font-size: 18px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 25px;
                    border-radius: 8px;
                    word-break: break-all;
                    line-height: 1.6;
                    box-shadow: 0 2px 8px rgba(102, 126, 234, 0.3);
                }
                .document-id {
                    margin-top: 20px;
                    font-size: 14px;
                    color: #666;
                }
                .document-id strong {
                    color: #333;
                }

                /* Block Confirmation Section */
                .confirmation-section {
                    background: white;
                    padding: 30px;
                    border-radius: 10px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }
                .section-title {
                    font-size: 20px;
                    color: #333;
                    margin-bottom: 20px;
                    padding-bottom: 10px;
                    border-bottom: 2px solid #667eea;
                }
                
                .stat-grid { 
                    display: grid; 
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
                    gap: 15px; 
                    margin: 20px 0; 
                }
                .stat-card { 
                    background: #f8f9fa;
                    padding: 20px; 
                    border-radius: 8px; 
                    text-align: center;
                    border: 2px solid #e9ecef;
                }
                .stat-value { 
                    font-size: 28px; 
                    font-weight: bold; 
                    color: #667eea;
                    margin: 10px 0; 
                }
                .stat-label { 
                    font-size: 12px; 
                    color: #666;
                    text-transform: uppercase; 
                    letter-spacing: 1px; 
                }
                
                .info-row { 
                    margin: 15px 0; 
                    padding: 15px; 
                    background: #f8f9fa;
                    border-radius: 5px;
                }
                .info-label { 
                    font-weight: bold; 
                    color: #555; 
                    display: block; 
                    margin-bottom: 8px; 
                    font-size: 12px; 
                    text-transform: uppercase; 
                    letter-spacing: 0.5px; 
                }
                .info-value { 
                    color: #333; 
                    font-size: 14px; 
                }
                .hash-box { 
                    font-family: 'Courier New', monospace; 
                    background: white; 
                    padding: 12px; 
                    word-break: break-all; 
                    border-radius: 5px; 
                    margin-top: 8px; 
                    font-size: 13px; 
                    line-height: 1.6;
                    border: 1px solid #dee2e6;
                }
                
                .loading { 
                    text-align: center; 
                    padding: 60px 20px; 
                    color: #666; 
                    font-size: 18px; 
                }
                .error { 
                    background: #ffebee; 
                    color: #c62828; 
                    padding: 20px; 
                    border-radius: 8px; 
                    border-left: 4px solid #c62828; 
                }
                .success-badge { 
                    display: inline-block; 
                    background: #4caf50; 
                    color: white; 
                    padding: 6px 15px; 
                    border-radius: 15px; 
                    font-size: 12px; 
                    font-weight: bold; 
                    margin-left: 10px; 
                }
                .timestamp {
                    color: #666;
                    font-size: 14px;
                    margin-top: 10px;
                }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🔍 Transaction Explorer</h1>
                <p>Transaction ID: <code style="background: rgba(255,255,255,0.2); padding: 5px 10px; border-radius: 4px;">${txId}</code></p>
                <a href="/" class="back-link">← Back to Hash Explorer</a>
            </div>
            
            <div id="content" class="loading">
                <div>⏳ Loading transaction details...</div>
            </div>

            <script>
                async function loadTransactionDetails() {
                    try {
                        const res = await fetch('/api/transaction/${txId}');
                        const data = await res.json();
                        
                        if (!data.success) {
                            document.getElementById('content').innerHTML = 
                                '<div class="error"><strong>❌ Error:</strong> ' + (data.error || 'Transaction not found') + '</div>';
                            return;
                        }
                        
                        const tx = data.transaction;
                        const block = data.blockInfo;
                        
                        let blockHtml = '';
                        if (block && block.success) {
                            blockHtml = \`
                                <div class="confirmation-section">
                                    <h2 class="section-title">
                                        📦 Blockchain Confirmation 
                                        <span class="success-badge">✓ VERIFIED</span>
                                    </h2>
                                    
                                    <div class="stat-grid">
                                        <div class="stat-card">
                                            <div class="stat-label">Block Number</div>
                                            <div class="stat-value">\${block.blockNumber !== null ? block.blockNumber : 'N/A'}</div>
                                        </div>
                                        <div class="stat-card">
                                            <div class="stat-label">Block Size</div>
                                            <div class="stat-value">\${block.blockSize ? (block.blockSize / 1024).toFixed(2) : 'N/A'}</div>
                                            <div class="stat-label" style="margin-top: 5px;">KB</div>
                                        </div>
                                        <div class="stat-card">
                                            <div class="stat-label">Transactions in Block</div>
                                            <div class="stat-value">\${block.transactionCount !== null ? block.transactionCount : 'N/A'}</div>
                                        </div>
                                        <div class="stat-card">
                                            <div class="stat-label">Channel</div>
                                            <div class="stat-value" style="font-size: 18px;">\${block.channel}</div>
                                        </div>
                                    </div>

                                    <div class="info-row">
                                        <span class="info-label">🔗 Previous Block Hash</span>
                                        <div class="hash-box">\${block.previousBlockHash || 'N/A'}</div>
                                    </div>
                                    
                                    <div class="info-row">
                                        <span class="info-label">📊 Block Data Hash</span>
                                        <div class="hash-box">\${block.dataHash || 'N/A'}</div>
                                    </div>
                                </div>
                            \`;
                        } else {
                            blockHtml = '<div class="error">⚠️ Block confirmation details not available</div>';
                        }
                        
                        document.getElementById('content').innerHTML = \`
                            <div class="data-hash-section">
                                <div class="data-hash-title">📄 YOUR SUBMITTED DATA HASH</div>
                                <div class="data-hash-value">\${tx.dataHash}</div>
                                <div class="document-id">
                                    <strong>Document ID:</strong> \${tx.documentId}
                                </div>
                                \${tx.timestamp ? \`<div class="timestamp">⏰ Stored: \${tx.timestamp}</div>\` : ''}
                            </div>
                            
                            \${blockHtml}
                        \`;
                    } catch (error) {
                        document.getElementById('content').innerHTML = 
                            '<div class="error"><strong>❌ Error loading transaction:</strong> ' + error.message + '</div>';
                    }
                }
                
                window.onload = loadTransactionDetails;
            </script>
        </body>
        </html>
    `);
});

// Block Explorer Page - Pretty HTML display for block info
app.get('/block/:txId', (req, res) => {
    const { txId } = req.params;
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Block Info - ${txId}</title>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body { font-family: sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; background: #f5f7fa; }
                .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }
                .back-link { color: white; text-decoration: none; display: inline-block; margin-top: 10px; opacity: 0.9; }
                .back-link:hover { opacity: 1; text-decoration: underline; }
                .block-container { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
                .block-info { background: #e3f2fd; padding: 20px; margin: 20px 0; border-radius: 8px; border-left: 4px solid #2196F3; }
                .info-row { margin: 15px 0; padding: 12px; border-bottom: 1px solid #eee; }
                .info-row:last-child { border-bottom: none; }
                .label { font-weight: bold; color: #555; display: block; margin-bottom: 5px; font-size: 14px; text-transform: uppercase; letter-spacing: 0.5px; }
                .value { color: #333; font-size: 16px; }
                .hash { font-family: monospace; background: #f8f9fa; padding: 12px; word-break: break-all; border-radius: 5px; margin-top: 8px; font-size: 13px; line-height: 1.6; }
                .loading { text-align: center; padding: 60px 20px; color: #666; font-size: 18px; }
                .error { background: #ffebee; color: #c62828; padding: 20px; border-radius: 8px; border-left: 4px solid #c62828; }
                .success-badge { display: inline-block; background: #4caf50; color: white; padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: bold; margin-left: 10px; }
                .error-badge { display: inline-block; background: #f44336; color: white; padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: bold; margin-left: 10px; }
                .stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 20px 0; }
                .stat-card { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; text-align: center; }
                .stat-value { font-size: 32px; font-weight: bold; margin: 10px 0; }
                .stat-label { font-size: 14px; opacity: 0.9; text-transform: uppercase; letter-spacing: 1px; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>📦 PARA Block Explorer</h1>
                <p>Transaction ID: <code style="background: rgba(255,255,255,0.2); padding: 5px 10px; border-radius: 4px;">${txId}</code></p>
                <a href="/" class="back-link">← Back to Hash Explorer</a>
            </div>
            
            <div class="block-container">
                <div id="content" class="loading">
                    <div>⏳ Loading block information...</div>
                </div>
            </div>

            <script>
                async function loadBlockInfo() {
                    try {
                        const res = await fetch('/api/block/txid/${txId}');
                        const data = await res.json();
                        
                        if (!data.success) {
                            document.getElementById('content').innerHTML = 
                                '<div class="error"><strong>❌ Error:</strong> ' + (data.error || 'Block not found') + '</div>';
                            return;
                        }
                        
                        document.getElementById('content').innerHTML = \`
                            <h2>Block Information <span class="success-badge">✓ FOUND</span></h2>
                            
                            <div class="stat-grid">
                                <div class="stat-card">
                                    <div class="stat-label">Block Number</div>
                                    <div class="stat-value">\${data.blockNumber !== null ? data.blockNumber : 'N/A'}</div>
                                </div>
                                <div class="stat-card">
                                    <div class="stat-label">Block Size</div>
                                    <div class="stat-value">\${data.blockSize ? (data.blockSize / 1024).toFixed(2) : 'N/A'} KB</div>
                                </div>
                                <div class="stat-card">
                                    <div class="stat-label">Transactions</div>
                                    <div class="stat-value">\${data.transactionCount !== null ? data.transactionCount : 'N/A'}</div>
                                </div>
                            </div>

                            <div class="block-info">
                                <div class="info-row">
                                    <span class="label">🆔 Transaction ID</span>
                                    <div class="hash">\${data.transactionId}</div>
                                </div>
                                
                                <div class="info-row">
                                    <span class="label">📺 Channel</span>
                                    <span class="value">\${data.channel}</span>
                                </div>
                                
                                <div class="info-row">
                                    <span class="label">🔗 Previous Block Hash</span>
                                    <div class="hash">\${data.previousBlockHash || 'N/A'}</div>
                                </div>
                                
                                <div class="info-row">
                                    <span class="label">📊 Data Hash</span>
                                    <div class="hash">\${data.dataHash || 'N/A'}</div>
                                </div>
                            </div>
                        \`;
                    } catch (error) {
                        document.getElementById('content').innerHTML = 
                            '<div class="error"><strong>❌ Error loading block info:</strong> ' + error.message + '</div>';
                    }
                }
                
                window.onload = loadBlockInfo;
            </script>
        </body>
        </html>
    `);
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

// Web Interface (Updated to show block info)
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
                input { padding: 12px; width: 400px; font-size: 16px; border: 1px solid #ddd; border-radius: 5px; }
                button { padding: 12px 24px; background: #667eea; color: white; border: none; cursor: pointer; margin-left: 10px; border-radius: 5px;}
                button:hover { background: #5568d3; }
                .result { background: white; padding: 20px; margin: 15px 0; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
                .hash { font-family: monospace; background: #f8f9fa; padding: 10px; word-break: break-all; border-radius: 5px; margin: 5px 0; }
                .block-info { background: #e3f2fd; padding: 15px; margin-top: 15px; border-radius: 5px; font-size: 14px; border-left: 4px solid #2196F3; }
                .label { font-weight: bold; color: #555; display: inline-block; min-width: 150px; }
                .value { color: #333; }
                .info-row { margin: 8px 0; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🔍 Veridat Hash Explorer</h1>
                <p>Query blockchain data with comprehensive block information</p>
            </div>
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
                        displayDetailed(data);
                    } else {
                        document.getElementById('results').innerHTML = '<div class="result">Not found</div>';
                    }
                }
                function display(items) {
                    if(!items || !items.length) { 
                        document.getElementById('results').innerHTML = '<div class="result">No results</div>'; 
                        return; 
                    }
                    document.getElementById('results').innerHTML = items.map(i => 
                        \`<div class="result">
                            <div class="info-row"><span class="label">Document ID:</span> <span class="value">\${i.documentID}</span></div>
                            <div class="info-row"><span class="label">Hash:</span></div>
                            <div class="hash">\${i.hash}</div>
                            <div class="info-row"><span class="label">Transaction ID:</span></div>
                            <div class="hash">\${i.txId || 'N/A'}</div>
                            <div class="info-row"><span class="label">Timestamp:</span> <span class="value">\${i.timestamp || 'N/A'}</span></div>
                        </div>\`
                    ).join('');
                }
                function displayDetailed(result) {
                    if(!result || !result.data) {
                        document.getElementById('results').innerHTML = '<div class="result">No data</div>';
                        return;
                    }
                    const i = result.data;
                    const block = result.blockInfo;
                    let blockHtml = '';
                    if(block && block.success) {
                        blockHtml = \`
                            <div class="block-info">
                                <strong>📦 Blockchain Information</strong>
                                <div class="info-row"><span class="label">Block Number:</span> <strong>\${block.blockNumber}</strong></div>
                                <div class="info-row"><span class="label">Channel:</span> \${block.channel}</div>
                                <div class="info-row"><span class="label">Block Size:</span> \${block.blockSize} bytes</div>
                                <div class="info-row"><span class="label">Transaction Count:</span> \${block.transactionCount}</div>
                                <div class="info-row"><span class="label">Previous Block Hash:</span></div>
                                <div class="hash">\${block.previousBlockHash || 'N/A'}</div>
                                <div class="info-row"><span class="label">Data Hash:</span></div>
                                <div class="hash">\${block.dataHash || 'N/A'}</div>
                            </div>
                        \`;
                    }
                    document.getElementById('results').innerHTML = \`
                        <div class="result">
                            <div class="info-row"><span class="label">Document ID:</span> <span class="value">\${i.documentID}</span></div>
                            <div class="info-row"><span class="label">Hash:</span></div>
                            <div class="hash">\${i.hash}</div>
                            <div class="info-row"><span class="label">Transaction ID:</span></div>
                            <div class="hash">\${i.txId || 'N/A'}</div>
                            <div class="info-row"><span class="label">Timestamp:</span> <span class="value">\${i.timestamp || 'N/A'}</span></div>
                            \${blockHtml}
                        </div>
                    \`;
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
    console.log(`📍 Doc Query:      http://localhost:${PORT}/api/hash/{documentId}`);
    console.log(`📍 Block Query:    http://localhost:${PORT}/api/block/txid/{txId}`);
    console.log(`📍 Block Page:     http://localhost:${PORT}/block/{txId}`);
    console.log(`📍 Transaction:    http://localhost:${PORT}/transaction/{txId}`);
    console.log(`📍 Health Check:   http://localhost:${PORT}/health`);
});