// js/app.js
// THE BODY: Handles Navigation (Routing) and HTML Templates.

const templates = {
    dashboard: `
        <div class="module-wrapper" style="width: 95%; max-width: 1200px;">
            <div class="module-header">
                <h1>GLOBAL THREAT INTEL</h1>
                <p>Real-time Attack Vectors & Zero-Day Alerts</p>
            </div>
            
            <div class="glass-panel" style="padding:0; overflow:hidden; position:relative; min-height:600px;">
                
                <div style="width:100%; height:500px; border-bottom:1px solid var(--gold);">
                    <iframe src="https://threatmap.fortiguard.com/" 
                            style="width:100%; height:100%; border:none; filter: invert(1) hue-rotate(180deg) contrast(1.2);">
                    </iframe>
                    </div>

                <div style="height:100px; background:rgba(0,0,0,0.8); padding:15px; display:flex; flex-direction:column; justify-content:center;">
                    <div style="color:var(--cyan); font-size:0.8rem; letter-spacing:2px; margin-bottom:5px; font-weight:bold;">
                        <i class="fa-solid fa-satellite-dish"></i> INCOMING INTEL FEED
                    </div>
                    <div class="news-ticker-container" style="overflow:hidden; white-space:nowrap; position:relative;">
                        <div id="news-ticker" style="display:inline-block; animation: ticker 30s linear infinite; color:#fff;">
                            <span style="color:#666;">Initializing Uplink...</span>
                        </div>
                    </div>
                </div>

            </div>
        </div>
    `,
    phishing: `
        <div class="module-wrapper">
            <div class="module-header"><h1>PHISHING DETECTOR</h1><p>Analyze suspicious URLs</p></div>
            <div class="glass-panel">
                <div class="input-group"><label>TARGET URL</label><input type="text" id="phish-url" placeholder="https://example.com/login"></div>
                <button class="cyber-btn" onclick="ModuleSystem.scanURL()">INITIATE SCAN</button>
                <div class="console-output" id="terminal"></div>
            </div>
        </div>
    `,
    malware: `
        <div class="module-wrapper">
            <div class="module-header"><h1>MALWARE SANDBOX</h1><p>Heuristic file analysis</p></div>
            <div class="glass-panel">
                <div class="input-group"><label>UPLOAD FILE</label><input type="file" id="malware-file"></div>
                <button class="cyber-btn cyan" onclick="ModuleSystem.scanFile()">ANALYZE SIGNATURE</button>
                <div class="console-output" id="terminal"></div>
            </div>
        </div>
    `,
    
    steganography: `
        <div class="module-wrapper" id="p-stego">
            <div class="module-header"><h1>STEGO LAB</h1><p>LSB Pixel Manipulation & Detection</p></div>
            
            <div class="glass-panel" style="display:grid; grid-template-columns: 1fr 1fr; gap:40px; align-items:start;">
                
                <div style="border-right:1px solid rgba(212,175,55,0.2); padding-right:40px;">
                    <h3 style="color:var(--gold); border-bottom:1px solid var(--gold); margin-bottom:15px; padding-bottom:5px;">ENCODE</h3>
                    
                    <div class="input-group">
                        <label>SOURCE IMAGE</label>
                        <input type="file" id="stego-enc-file">
                    </div>
                    
                    <div class="input-group">
                        <label>SECRET MESSAGE</label>
                        <input type="text" id="stego-msg" placeholder="Confidential data...">
                    </div>
                    
                    <button class="cyber-btn" onclick="ModuleSystem.encodeStego()" style="width:100%;">ENCODE & HIDE</button>
                    
                    <div id="stego-download-area" style="display:none; margin-top:20px; text-align:center; background:rgba(0,255,0,0.1); padding:10px; border:1px solid #0f0;">
                        <p style="color:#0f0; margin-bottom:10px;">✅ Encoding Complete</p>
                        <a id="stego-download-link" href="#" class="cyber-btn cyan" style="text-decoration:none; display:inline-block;">DOWNLOAD IMAGE</a>
                    </div>
                </div>

                <div>
                    <h3 style="color:var(--cyan); border-bottom:1px solid var(--cyan); margin-bottom:15px; padding-bottom:5px;">DECODE</h3>
                    
                    <div class="input-group">
                        <label>SUSPICIOUS IMAGE</label>
                        <input type="file" id="stego-dec-file" style="border-color:var(--cyan);">
                    </div>
                    
                    <button class="cyber-btn cyan" onclick="ModuleSystem.decodeStego()" style="width:100%;">SCAN FOR MESSAGES</button>
                    
                    <div id="stego-result-box" style="margin-top:20px; min-height:100px; background:rgba(0,0,0,0.5); border:1px dashed #666; padding:15px; word-wrap: break-word;">
                        <span style="color:#666; font-size:0.9rem;">> Waiting for analysis...</span>
                    </div>
                </div>

            </div>

            <div class="glass-panel" style="margin-top:20px; min-height:150px;">
                <div class="console-output" id="terminal">
                    <div class="log-entry">> Stego Lab Initialized. Ready for operations.</div>
                </div>
            </div>
        </div>
    `,
    qr: `
        <div class="module-wrapper">
            <div class="module-header"><h1>QR GUARD</h1><p>Secure Generation & Fraud Detection</p></div>
            <div class="glass-panel" style="display:grid; grid-template-columns: 1fr 1fr; gap:40px; align-items:start;">
                
                <!-- SECTION 1: GENERATOR -->
                <div style="border-right:1px solid rgba(212,175,55,0.2); padding-right:40px;">
                    <h3 style="color:var(--gold); border-bottom:1px solid var(--gold); padding-bottom:10px; margin-bottom:20px;">GENERATOR</h3>
                    
                    <div class="input-group">
                        <label>CONTENT TO ENCODE</label>
                        <input type="text" id="qr-input" placeholder="https://secure-site.com" style="width:100%;">
                    </div>
                    <button class="cyber-btn" onclick="ModuleSystem.generateQR()" style="width:100%; margin-bottom:20px;">GENERATE CODE</button>
                    
                    <!-- Result Area -->
                    <div id="qr-result-area" style="min-height:180px; border:2px dashed #444; background:rgba(0,0,0,0.3); display:flex; flex-direction:column; align-items:center; justify-content:center; padding:15px;">
                        <img id="qr-image" src="" style="display:none; width:140px; height:140px; border:4px solid #fff; margin-bottom:10px;">
                        <div id="qr-dl-container" style="display:none;">
                            <a id="qr-download-btn" href="#" class="cyber-btn cyan" style="padding:5px 15px; font-size:0.8rem; text-decoration:none;">DOWNLOAD QR</a>
                        </div>
                        <span id="qr-placeholder" style="color:#666; font-size:0.8rem;">PREVIEW AREA</span>
                    </div>
                </div>

                <!-- SECTION 2: FRAUD SCANNER -->
                <div>
                    <h3 style="color:var(--cyan); border-bottom:1px solid var(--cyan); padding-bottom:10px; margin-bottom:20px;">FRAUD SCANNER</h3>
                    
                    <div class="input-group">
                        <label>UPLOAD SUSPICIOUS QR</label>
                        <input type="file" id="qr-scan-file" style="border:1px solid var(--cyan);">
                    </div>
                    <button class="cyber-btn cyan" onclick="ModuleSystem.scanQR()" style="width:100%; margin-bottom:20px;">ANALYZE IMAGE</button>
                    
                    <div class="console-output" id="terminal" style="height:180px; border-color:var(--cyan);">
                        <div class="log-entry" style="color:#666;">> System Ready for Analysis...</div>
                    </div>
                </div>

            </div>
        </div>
    `,
        password: `
        <div class="module-wrapper">
            <div class="module-header"><h1>PASS GEN</h1><p>High-Entropy Key Generator</p></div>
            <div class="glass-panel">
                
                <div class="input-group">
                    <label>LENGTH: <span id="pass-len-display" style="color:var(--cyan)">16</span></label>
                    <input type="range" id="pass-slider" min="8" max="64" value="16" style="width:100%" 
                           oninput="ModuleSystem.updatePassLength(this.value)">
                </div>

                <div style="display:grid; grid-template-columns: 1fr 1fr; gap:15px; margin: 20px 0; padding:15px; background:rgba(0,0,0,0.3); border:1px solid #444;">
                    <div style="display:flex; align-items:center; gap:10px;">
                        <input type="checkbox" id="cb-upper" checked style="accent-color:var(--cyan); transform:scale(1.2);">
                        <label for="cb-upper" style="color:#fff; cursor:pointer;">Uppercase (A-Z)</label>
                    </div>
                    <div style="display:flex; align-items:center; gap:10px;">
                        <input type="checkbox" id="cb-lower" checked style="accent-color:var(--cyan); transform:scale(1.2);">
                        <label for="cb-lower" style="color:#fff; cursor:pointer;">Lowercase (a-z)</label>
                    </div>
                    <div style="display:flex; align-items:center; gap:10px;">
                        <input type="checkbox" id="cb-num" checked style="accent-color:var(--cyan); transform:scale(1.2);">
                        <label for="cb-num" style="color:#fff; cursor:pointer;">Numbers (0-9)</label>
                    </div>
                    <div style="display:flex; align-items:center; gap:10px;">
                        <input type="checkbox" id="cb-sym" checked style="accent-color:var(--cyan); transform:scale(1.2);">
                        <label for="cb-sym" style="color:#fff; cursor:pointer;">Symbols (!@#)</label>
                    </div>
                </div>

                <button class="cyber-btn cyan" onclick="ModuleSystem.generatePass()">GENERATE KEY</button>
                <div class="console-output" id="terminal"></div>
            </div>
        </div>
    `,
    encryption: `
        <div class="module-wrapper">
            <div class="module-header"><h1>CRYPTO VAULT</h1><p>AES-256 Text Encryption</p></div>
            <div class="glass-panel">
                
                <div class="input-group" style="margin-bottom:15px;">
                    <label>SECRET KEY (PASSWORD)</label>
                    <input type="password" id="crypto-key" placeholder="Enter encryption key..." style="width:100%;">
                </div>

                <div class="input-group">
                    <label>DATA TO SECURE</label>
                    <textarea id="crypto-text" rows="6" placeholder="Enter confidential notes here..." 
                        style="width:100%; background:rgba(0,0,0,0.3); color:#fff; border:1px solid var(--gold); padding:15px; font-family:monospace; resize:none;"></textarea>
                </div>
                
                <div style="display:flex; gap:20px; margin-top:20px;">
                    <button class="cyber-btn" onclick="ModuleSystem.encrypt()" style="flex:1;">
                        <i class="fa-solid fa-lock"></i> ENCRYPT
                    </button>
                    <button class="cyber-btn cyan" onclick="ModuleSystem.decrypt()" style="flex:1;">
                        <i class="fa-solid fa-unlock"></i> DECRYPT
                    </button>
                </div>

                <div class="console-output" id="terminal" style="margin-top:20px;">
                    <div class="log-entry">> Crypto Module Loaded. Waiting for Key...</div>
                </div>
            </div>
        </div>
    `,
    
    history: `
        <div class="module-wrapper">
            <div class="module-header"><h1>ACTIVITY LOGS</h1><p>Session Audit Trail</p></div>
            <div class="glass-panel" style="max-height: 500px; overflow-y: auto;">
                <table style="width:100%; color:#aaa; border-collapse:collapse; font-size:0.9rem;">
                    <thead>
                        <tr style="border-bottom:1px solid #333; color:var(--gold); text-align:left;">
                            <th style="padding:15px;">TIME</th>
                            <th style="padding:15px;">MODULE</th>
                            <th style="padding:15px;">ACTION</th>
                            <th style="padding:15px;">STATUS</th>
                        </tr>
                    </thead>
                    <tbody id="history-table-body">
                        <tr><td colspan="4" style="text-align:center; padding:20px;">Loading logs...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    `,
    about: `
        <div class="module-wrapper">
            <div class="module-header"><h1>ABOUT CRYPTA GUARD</h1></div>
            <div class="glass-panel">
                <p>Crypta Guard is an elite cybersecurity platform designed for secure communication and threat analysis.</p>
                <p>Version 1.0.0 | Secure Node Active</p>
            </div>
        </div>
    `,
    chatbot: `
        <div class="module-wrapper">
            <div class="module-header"><h1>AI ASSISTANT</h1></div>
            <div class="glass-panel">
                <div class="console-output" id="ai-terminal" style="height:300px; overflow-y:auto; margin-bottom:20px;">
                    <div class="log-entry">> AI System Online. How can I assist you agent?</div>
                </div>
                <div class="input-group">
                    <input type="text" id="ai-input" placeholder="Ask about phishing, malware, passwords...">
                </div>
                <button class="cyber-btn cyan" onclick="ModuleSystem.askAI()">QUERY SYSTEM</button>
            </div>
        </div>
    `,
    support: `
        <div class="module-wrapper">
            <div class="module-header"><h1>SECURE COMM-LINK</h1><p>Encrypted P2P Relay</p></div>
            <div class="glass-panel" style="padding:0; overflow:hidden; display:flex; height:500px;">
                
                <div style="width:30%; border-right:1px solid rgba(212,175,55,0.2); background:rgba(0,0,0,0.3); display:flex; flex-direction:column;">
                    <div style="padding:15px; background:rgba(212, 175, 55, 0.15); border-bottom:1px solid var(--gold); text-align:center;">
                        <small style="color:#aaa; font-size:0.7rem; letter-spacing:1px;">MY AGENT ID</small>
                        <div style="color:var(--gold); font-weight:bold; font-size:1.1rem; text-shadow:0 0 10px rgba(212,175,55,0.5);">
                            ${document.body.getAttribute('data-username') || 'UNKNOWN'}
                        </div>
                    </div>
                    <div style="padding:15px; border-bottom:1px solid rgba(255,255,255,0.1);">
                        <input type="text" id="user-search" placeholder="Enter Friend's Agent ID..." style="width:100%; padding:8px; font-size:0.8rem; background:rgba(0,0,0,0.5); border:1px solid #333; color:#fff;">
                        <button class="cyber-btn" onclick="ChatSystem.searchUser()" style="width:100%; margin-top:5px; padding:5px; font-size:0.7rem;">ADD AGENT</button>
                    </div>
                    <div id="friend-list" style="padding:10px; overflow-y:auto; flex:1;">
                        <div style="color:#666; font-size:0.8rem; text-align:center; margin-top:20px;">Scanning for links...</div>
                    </div>
                </div>

                <div style="width:70%; display:flex; flex-direction:column;">
                    <div id="chat-header" style="padding:15px; background:rgba(212,175,55,0.1); border-bottom:1px solid var(--gold); color:var(--gold); font-weight:bold; font-size:0.9rem;">
                        SELECT AGENT TO BEGIN ENCRYPTED UPLINK
                    </div>
                    <div id="chat-window" style="flex:1; padding:20px; overflow-y:auto; display:flex; flex-direction:column; gap:10px; background:rgba(0,0,0,0.2);"></div>
                    <div style="padding:15px; border-top:1px solid rgba(255,255,255,0.1); display:flex; gap:10px; background:rgba(0,0,0,0.4);">
                        <input type="text" id="msg-input" placeholder="Type encrypted message..." style="flex:1; padding:10px; background:rgba(0,0,0,0.5); border:1px solid #444; color:#fff;">
                        <button class="cyber-btn cyan" onclick="ChatSystem.sendMessage()" style="padding:10px 20px;">SEND</button>
                    </div>
                </div>
            </div>
        </div>
    `
};

function router(moduleName) {
    // 1. DEFINE PROTECTED ZONES HERE
    // 'support' is the internal name for the Secure Chat module
    // 'chatbot' is the internal name for the AI Assistant
    const protectedModules = ['history', 'support', 'chatbot']; 
    
    // 2. Check Login Status
    const isLoggedIn = document.body.getAttribute('data-logged-in') === 'true';

    // 3. The Security Gate
    if (protectedModules.includes(moduleName) && !isLoggedIn) {
        if(confirm("⚠ ACCESS DENIED: Encrypted Channel.\n\nThis module requires Agent Authorization.\nRedirect to Login?")) {
            window.location.href = "/login";
        }
        return; // Stop access
    }

    // --- STANDARD ROUTING LOGIC ---
    document.getElementById('hero-slider').classList.add('hidden');
    
    const dock = document.getElementById('main-dock');
    if(dock) dock.style.display = 'none';

    const container = document.getElementById('module-container');
    const content = document.getElementById('module-content');
    container.classList.remove('hidden');
    
    if(templates[moduleName]) {
        content.innerHTML = templates[moduleName];
        
        // Initialize logic for specific modules
        if(moduleName === 'support' && isLoggedIn) setTimeout(() => ChatSystem.init(), 100);
        if(moduleName === 'history' && isLoggedIn) setTimeout(() => ModuleSystem.loadHistory(), 100);
        if(moduleName === 'dashboard') setTimeout(() => ModuleSystem.loadNews(), 100);
    } else {
        content.innerHTML = `<h1 style="text-align:center; margin-top:100px;">COMING SOON</h1>`;
    }
}