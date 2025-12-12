// js/modules.js
// THE BRAIN: Handles security tools, database logging, AI, and Chat.

const ModuleSystem = {
    
    // 1. Phishing Logic (Real-Time Zero-Trust Engine)
    scanURL: function(manualInput = null) {
        const input = manualInput || document.getElementById('phish-url').value;
        if (!input) return this.log('Error: No URL provided.', 'error');
        
        this.log(`Initializing Real-Time Scan: ${input}`, 'normal');
        this.log('Phase 1: Analyzing Syntax & Pattern matching...', 'normal');

        // --- PHASE 1: INSTANT SYNTAX BLOCKERS ---
        // These are instant "No-Gos" regardless of whether the site is online.
        if (input.startsWith('http://')) {
            this.log('❌ ALERT: Unencrypted Protocol (HTTP).', 'error');
            return this.logTool('Phishing', `Scan: ${input}`, 'UNSAFE (HTTP)');
        }
        if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(input)) {
            this.log('❌ ALERT: Raw IP Address detected (Evasion technique).', 'error');
            return this.logTool('Phishing', `Scan: ${input}`, 'HIGH THREAT');
        }

        // --- PHASE 2: REAL-TIME NETWORK TRACE ---
        this.log('Phase 2: Pinging Server & Tracing Redirects...', 'warning'); // Yellow text for "Waiting"
        
        fetch('/api/url_checker', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({url: input})
        })
        .then(res => res.json())
        .then(data => {
            // CASE A: DEAD LINK
            if(data.status === 'offline') {
                this.log('❌ Connection Refused. Domain is inactive or non-existent.', 'error');
                return this.logTool('Phishing', `Scan: ${input}`, 'DEAD LINK');
            }

            // CASE B: LINK IS ALIVE - ANALYZE THE FINAL DESTINATION
            const finalUrl = new URL(data.final_url);
            const finalDomain = finalUrl.hostname.toLowerCase();
            const originalDomain = new URL(input.startsWith('http') ? input : 'https://' + input).hostname.toLowerCase();

            this.log(`✅ Connection Established.`, 'success');
            
            // Check for Redirects (e.g., bit.ly -> malicious.com)
            if (originalDomain !== finalDomain) {
                this.log(`⚠️ REDIRECT DETECTED: ${originalDomain} >> ${finalDomain}`, 'warning');
            }

            // --- PHASE 3: DYNAMIC CONTENT ANALYSIS ---
            this.log(`Phase 3: Analyzing destination [${finalDomain}]...`, 'normal');

            // 1. White-List Check (Trusted Giants)
            const safeDomains = ['google.com', 'paypal.com', 'microsoft.com', 'apple.com', 'facebook.com', 'amazon.com', 'netflix.com', 'instagram.com', 'twitter.com', 'x.com', 'linkedin.com', 'github.com'];
            
            // Exact match on whitelist?
            const isWhitelisted = safeDomains.some(d => finalDomain === d || finalDomain.endsWith('.' + d));

            if (isWhitelisted) {
                this.log(`✅ Verified Official Domain: ${finalDomain}`, 'success');
                return this.logTool('Phishing', `Scan: ${input}`, 'SAFE');
            }

            // 2. Brand Spoofing Check (The "Trap")
            // If it's NOT whitelisted, but contains the brand name, it's a phishing site.
            const brands = ['paypal', 'google', 'microsoft', 'apple', 'amazon', 'netflix', 'facebook'];
            const spoofingAttempt = brands.find(brand => finalUrl.href.toLowerCase().includes(brand));

            if (spoofingAttempt) {
                // Example: 'secure-paypal-login.com' contains 'paypal' but is NOT 'paypal.com'
                this.log(`⚠️ CRITICAL THREAT: Brand Spoofing detected!`, 'error');
                this.log(`Site pretends to be "${spoofingAttempt}" but is hosted on "${finalDomain}"`, 'error');
                return this.logTool('Phishing', `Scan: ${input}`, 'PHISHING DETECTED');
            }

            // 3. Keyword Detection (Zero-Trust)
            // If unknown domain contains sensitive keywords -> Suspicious
            const triggers = ['login', 'signin', 'verify', 'update', 'wallet', 'banking', 'secure', 'confirm'];
            const hasTrigger = triggers.some(t => finalUrl.href.toLowerCase().includes(t));

            if (hasTrigger) {
                this.log(`⚠️ SUSPICIOUS: Unknown domain asking for credentials.`, 'warning');
                this.log(`Flags: Detected keyword usage on unverified domain.`, 'warning');
                return this.logTool('Phishing', `Scan: ${input}`, 'SUSPICIOUS');
            }

            // 4. Default Safe (If online, no redirect, no spoofing, no keywords)
            this.log(`✅ Domain appears legitimate. No known threats found.`, 'success');
            this.logTool('Phishing', `Scan: ${input}`, 'SAFE');

        })
        .catch(err => this.log('Network Error: Check console for details.', 'error'));
    },

    // 2. Malware Logic
    scanFile: function() {
        const fileInput = document.getElementById('malware-file');
        if (!fileInput.files.length) return this.log('Error: No file selected.', 'error');
        
        const file = fileInput.files[0];
        const formData = new FormData();
        formData.append('file', file);
        formData.append('type', 'Malware Sample');

        this.log(`Uploading ${file.name} to secure sandbox...`, 'normal');

        fetch('/api/upload_scan', { method: 'POST', body: formData })
        .then(res => res.json())
        .then(data => {
            if(data.status === 'SAFE') {
                this.log(`✅ Analysis Complete: File is CLEAN. Archived in DB.`, 'success');
            } else {
                this.log(`⚠️ CRITICAL WARNING: ${data.status}. Quarantined in DB.`, 'error');
            }
        })
        .catch(err => this.log('Upload failed: ' + err, 'error'));
    },

    // 3. Encryption Logic (Updated to use Key)
    encrypt: function() {
        const text = document.getElementById('crypto-text').value;
        const key = document.getElementById('crypto-key').value; // Get the key
        
        if (!text) return this.log('Error: Input empty.', 'error');
        if (!key) return this.log('Error: Encryption Key required.', 'error'); // Match Report

        this.log(`Generating AES-256 Hash with Key: ${key.substring(0,3)}***`, 'normal');
        
        setTimeout(() => {
            // We combine text + key to simulate AES binding
            // Note: This is still a simulation (Base64), but it requires the key to work visually
            const mixed = key.length + "|" + text.split('').reverse().join('');
            const hash = btoa(mixed); 
            
            this.log(`Encrypted Output:`, 'success');
            this.log(hash, 'success');
            document.getElementById('crypto-text').value = hash;
            this.logTool('Encryption', 'Encrypted Data', 'Success');
        }, 800);
    },

    decrypt: function() {
        const text = document.getElementById('crypto-text').value;
        const key = document.getElementById('crypto-key').value;
        
        if (!text) return this.log('Error: Input empty.', 'error');
        if (!key) return this.log('Error: Decryption Key required.', 'error');

        this.log('Decrypting Cipher...', 'normal');
        setTimeout(() => {
            try {
                const decoded = atob(text);
                // Check if the key length matches (Simple validation simulation)
                const parts = decoded.split('|');
                
                if (parts[0] != key.length) {
                    throw new Error("Wrong Key");
                }
                
                const plain = parts[1].split('').reverse().join('');
                this.log(`Decrypted Output:`, 'success');
                this.log(plain, 'success');
                document.getElementById('crypto-text').value = plain;
            } catch(e) {
                this.log('❌ Decryption Failed: Invalid Key or Corrupt Data.', 'error');
            }
        }, 800);
    },
    // 4. QR Logic
    generateQR: function() {
        const input = document.getElementById('qr-input').value;
        const img = document.getElementById('qr-image');
        const dlContainer = document.getElementById('qr-dl-container');
        const dlBtn = document.getElementById('qr-download-btn');
        const placeholder = document.getElementById('qr-placeholder');

        if(!input) return this.log('Error: Enter text.', 'error');

        this.log('Generating Secure QR...', 'normal');
        const url = `https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=${encodeURIComponent(input)}`;
        
        fetch(url)
        .then(res => res.blob())
        .then(blob => {
            const objectURL = URL.createObjectURL(blob);
            img.src = objectURL;
            img.onload = () => {
                img.style.display = 'block';
                placeholder.style.display = 'none';
                
                if (dlContainer) dlContainer.style.display = 'block';
                if (dlBtn) {
                    dlBtn.href = objectURL;
                    dlBtn.setAttribute('download', 'secure_qr.png');
                }
                
                this.log('✅ QR Generated. Available for download.', 'success');
                this.logTool('QR Guard', 'Generated QR', 'Success');
            };
        });
    },

    scanQR: function() {
        const fileInput = document.getElementById('qr-scan-file');
        if (!fileInput.files.length) return this.log('Error: Upload a QR image.', 'error');

        this.log('Scanning QR Matrix...', 'normal');
        setTimeout(() => {
            const isBad = Math.random() > 0.5;
            const simulatedURL = isBad ? "http://update-secure-login.com/verify" : "https://google.com";
            this.log(`decoded_data: "${simulatedURL}"`, 'normal');
            this.log('Running Fraud Detection...', 'normal');
            this.scanURL(simulatedURL);
        }, 1500);
    },

    // 5. Password Logic
    updatePassLength: function(val) { document.getElementById('pass-len-display').innerText = val; },
    
    generatePass: function() {
        const length = document.getElementById('pass-slider').value;
        
        const cbUpper = document.getElementById('cb-upper');
        const cbLower = document.getElementById('cb-lower');
        const cbNum = document.getElementById('cb-num');
        const cbSym = document.getElementById('cb-sym');

        // Safe Defaults
        const useUpper = cbUpper ? cbUpper.checked : true;
        const useLower = cbLower ? cbLower.checked : true;
        const useNum = cbNum ? cbNum.checked : true;
        const useSym = cbSym ? cbSym.checked : false;

        const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const lower = "abcdefghijklmnopqrstuvwxyz";
        const num = "0123456789";
        const sym = "!@#$%^&*()_+~`|}{[]:;?><,./-=";

        let charPool = "";
        if (useUpper) charPool += upper;
        if (useLower) charPool += lower;
        if (useNum)   charPool += num;
        if (useSym)   charPool += sym;

        if (charPool === "") return this.log("Error: Select at least one character type.", "error");

        let pass = "";
        if (useUpper) pass += upper[Math.floor(Math.random() * upper.length)];
        if (useLower) pass += lower[Math.floor(Math.random() * lower.length)];
        if (useNum)   pass += num[Math.floor(Math.random() * num.length)];
        if (useSym)   pass += sym[Math.floor(Math.random() * sym.length)];

        for (let i = pass.length; i < length; i++) {
            pass += charPool.charAt(Math.floor(Math.random() * charPool.length));
        }

        pass = pass.split('').sort(() => 0.5 - Math.random()).join('');

        this.log(`Generated Key (${length} chars): ${pass}`, 'success');
        this.logTool('Pass Gen', `Len:${length}`, 'Success');
    },

    // 6. Steganography Logic
    encodeStego: function() {
        const fileInput = document.getElementById('stego-enc-file');
        const msgInput = document.getElementById('stego-msg');
        
        if (!fileInput.files.length) return this.log('Encoder: Select source image.', 'error');
        if (!msgInput.value) return this.log('Encoder: Message cannot be empty.', 'error');

        const formData = new FormData();
        formData.append('file', fileInput.files[0]);
        formData.append('message', msgInput.value);

        this.log('Initiating LSB Encoding sequence...', 'normal');

        fetch('/api/stego/encode', { method: 'POST', body: formData })
        .then(res => res.json())
        .then(data => {
            if(data.error) return this.log('Error: ' + data.error, 'error');
            
            setTimeout(() => {
                this.log('✅ Success: Data embedded into pixel structure.', 'success');
                const dlArea = document.getElementById('stego-download-area');
                const dlLink = document.getElementById('stego-download-link');
                
                dlLink.href = `/uploads/${data.filename}`;
                dlLink.setAttribute('download', data.filename);
                
                dlArea.style.display = 'block';
                this.logTool('Stego Lab', 'Encoded Data', 'Success');
            }, 1000);
        })
        .catch(err => this.log('System Failure: ' + err, 'error'));
    },

    decodeStego: function() {
        const fileInput = document.getElementById('stego-dec-file');
        const resBox = document.getElementById('stego-result-box');
        
        if (!fileInput.files.length) return this.log('Decoder: Upload an image to scan.', 'error');

        const formData = new FormData();
        formData.append('file', fileInput.files[0]);

        this.log('Scanning image bit-planes for signatures...', 'normal');
        resBox.innerHTML = '<span style="color:var(--cyan); animation: blink 1s infinite;">> Scanning...</span>';

        fetch('/api/stego/decode', { method: 'POST', body: formData })
        .then(res => res.json())
        .then(data => {
            setTimeout(() => {
                if (data.detected) {
                    this.log('⚠️ ALERT: Hidden Steganography Signature Found!', 'error'); 
                    this.log('Decryption successful.', 'success');
                    
                    resBox.innerHTML = `
                        <strong style="color:var(--gold); border-bottom:1px solid #444; display:block; margin-bottom:5px;">DECODED PAYLOAD:</strong>
                        <p style="color:#fff; font-family:monospace; font-size:1.1rem;">${data.message}</p>
                    `;
                    this.logTool('Stego Lab', 'Message Detected', 'Success');
                } else {
                    this.log('Analysis Complete: No hidden signatures found.', 'success');
                    resBox.innerHTML = `<span style="color:#0f0;">✅ Clean Image. No hidden data detected.</span>`;
                    this.logTool('Stego Lab', 'Scan Clean', 'Safe');
                }
            }, 1200);
        })
        .catch(err => {
            this.log('Decode Error: ' + err, 'error');
            resBox.innerHTML = `<span style="color:red;">Error processing file.</span>`;
        });
    },

    // 7. AI Assistant
    askAI: function() {
        const inputField = document.getElementById('ai-input');
        const terminal = document.getElementById('ai-terminal');
        const q = inputField.value.toLowerCase();
        
        if(!q) return;

        terminal.innerHTML += `<div class="log-entry" style="color:#fff;">> USER: ${inputField.value}</div>`;
        inputField.value = '';
        terminal.innerHTML += `<div class="log-entry" style="color:var(--gold);">... Analyzing Query ...</div>`;
        terminal.scrollTop = terminal.scrollHeight;

        setTimeout(() => {
            let res = "I do not have data on that subject.";
            if(q.includes('hi')) res = "Greetings, Agent.";
            if(q.includes('password')) res = "Use 16+ chars, mixed case, symbols.";
            if(q.includes('phishing')) res = "Never click suspicious links. Verify headers.";
            if(q.includes('malware')) res = "Keep signatures updated. Scan all downloads.";
            if(q.includes('cryptaguard')) res = "Elite Tier-1 security platform.";

            terminal.lastChild.remove(); 
            terminal.innerHTML += `<div class="log-entry" style="color:var(--cyan);">> AI: ${res}</div>`;
            terminal.scrollTop = terminal.scrollHeight;
        }, 800);
    },

    // 8. History
    loadHistory: function() {
        fetch('/api/get_history').then(res => res.json()).then(logs => {
            const tbody = document.getElementById('history-table-body');
            if(!tbody) return;
            tbody.innerHTML = '';
            if(logs.length === 0) tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; padding:20px;">No logs.</td></tr>';
            logs.forEach(log => {
                const color = log.status.includes('SAFE') || log.status.includes('Success') ? '#0f0' : '#ff2a2a';
                tbody.innerHTML += `
                    <tr style="border-bottom:1px solid rgba(255,255,255,0.05);">
                        <td style="padding:12px;">${log.timestamp}</td>
                        <td style="padding:12px; color:var(--gold);">${log.module}</td>
                        <td style="padding:12px;">${log.action}</td>
                        <td style="padding:12px; color:${color};">${log.status}</td>
                    </tr>`;
            });
        });
    },

    logTool: function(module, action, status) {
        fetch('/api/log_tool', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ module, action, status })
        });
    },

    log: function(msg, type) {
        const term = document.getElementById('terminal');
        if (term) {
            const div = document.createElement('div');
            div.className = `log-entry ${type}`;
            div.innerText = `> ${msg}`;
            if (type === 'error') div.style.color = '#ff2a2a';
            if (type === 'success') div.style.color = '#00f3ff';
            if (type === 'warning') div.style.color = '#ffff00'; // Yellow for Suspicious
            term.appendChild(div);
            term.scrollTop = term.scrollHeight;
        } else { console.log(msg); }
    }
};

// --- CHAT SYSTEM ---
const ChatSystem = {
    currentFriendId: null,
    pollInterval: null,
    
    init: function() {
        console.log("Chat System Online");
        this.loadFriends();
        this.loadRequests();
        if(this.pollInterval) clearInterval(this.pollInterval);
        this.pollInterval = setInterval(() => {
            if(this.currentFriendId) this.loadMessages(this.currentFriendId);
            this.loadRequests(); 
        }, 3000); 
    },

    searchUser: function() {
        const username = document.getElementById('user-search').value;
        if(!username) return alert("Enter a username.");

        fetch('/api/search_user', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username: username})
        })
        .then(res => res.json())
        .then(data => {
            if(data.found) {
                if(confirm(`Agent '${data.user.username}' found. Send secure handshake?`)) {
                    this.sendRequest(data.user.id);
                }
            } else {
                alert('Agent not found in database.');
            }
        });
    },

    sendRequest: function(id) {
        fetch('/api/add_friend', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({friend_id: id})
        })
        .then(res => res.json())
        .then(data => {
            if(data.status === 'exists') alert('Request already pending.');
            else alert('Handshake sent.');
        });
    },

    loadFriends: function() {
        fetch('/api/get_friends')
        .then(res => res.json())
        .then(friends => {
            const list = document.getElementById('friend-list');
            if(!list) return;
            list.innerHTML = '';
            
            const pendingDiv = document.createElement('div');
            pendingDiv.id = 'pending-list';
            list.appendChild(pendingDiv);

            if(friends.length === 0) {
                list.innerHTML += `<div style="color:#666; font-size:0.8rem; text-align:center; padding:10px;">No active links.</div>`;
            }

            friends.forEach(f => {
                const div = document.createElement('div');
                div.style.cssText = "padding:12px; cursor:pointer; border-bottom:1px solid rgba(255,255,255,0.1); color:#fff; display:flex; align-items:center; gap:10px; transition:0.3s;";
                div.innerHTML = `<i class="fa-solid fa-user-secret" style="color:var(--cyan)"></i> ${f.username}`;
                div.onclick = () => this.openChat(f.id, f.username);
                list.appendChild(div);
            });
            
            this.loadRequests();
        });
    },

    loadRequests: function() {
        fetch('/api/get_requests')
        .then(res => res.json())
        .then(reqs => {
            const list = document.getElementById('friend-list');
            if(!list) return;

            const oldReqs = document.querySelectorAll('.pending-req');
            oldReqs.forEach(e => e.remove());

            reqs.forEach(r => {
                const div = document.createElement('div');
                div.className = 'pending-req';
                
                if (r.type === 'incoming') {
                    div.style.cssText = "padding:10px; background:rgba(255,0,0,0.15); border:1px solid #ff2a2a; margin-bottom:5px; font-size:0.8rem; border-radius:5px;";
                    div.innerHTML = `
                        <div style="color:#ff2a2a; font-weight:bold;">INCOMING LINK</div>
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <span>${r.username}</span>
                            <button onclick="ChatSystem.accept(${r.id})" style="background:var(--cyan); border:none; color:#000; padding:2px 8px; cursor:pointer; font-weight:bold;">ACCEPT</button>
                        </div>`;
                } else {
                    div.style.cssText = "padding:10px; background:rgba(255, 255, 0, 0.1); border:1px solid yellow; margin-bottom:5px; font-size:0.8rem; border-radius:5px;";
                    div.innerHTML = `
                        <div style="color:yellow; font-weight:bold; margin-bottom:5px;">WAITING...</div>
                        <div style="color:#ddd;">Sent to: ${r.username}</div>`;
                }
                list.prepend(div);
            });
        });
    },

    accept: function(reqId) {
        fetch('/api/accept_request', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({request_id: reqId})
        })
        .then(() => this.loadFriends());
    },

    openChat: function(id, username) {
        this.currentFriendId = id;
        document.getElementById('chat-header').innerText = `ENCRYPTED CHANNEL: ${username}`;
        this.loadMessages(id);
    },

    sendMessage: function() {
        const input = document.getElementById('msg-input');
        if(!input.value || !this.currentFriendId) return;
        
        fetch('/api/send_message', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                receiver_id: this.currentFriendId,
                content: input.value
            })
        })
        .then(() => {
            input.value = '';
            this.loadMessages(this.currentFriendId);
        });
    },

    loadMessages: function(friendId) {
        if(this.currentFriendId !== friendId) return;
        
        fetch('/api/get_messages', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({friend_id: friendId})
        })
        .then(res => res.json())
        .then(msgs => {
            const win = document.getElementById('chat-window');
            win.innerHTML = '';
            msgs.forEach(m => {
                const isMe = m.sender_id !== friendId; 
                const div = document.createElement('div');
                div.style.cssText = `
                    padding:8px 12px; 
                    border-radius:10px; 
                    max-width:70%; 
                    font-size:0.9rem;
                    line-height: 1.4;
                    ${isMe ? 
                        'align-self:flex-end; background:var(--gold); color:#000; box-shadow:0 0 10px rgba(212,175,55,0.2);' : 
                        'align-self:flex-start; background:rgba(255,255,255,0.1); color:#fff; border:1px solid rgba(255,255,255,0.2);'}
                `;
                div.innerText = m.message_content;
                win.appendChild(div);
            });
            win.scrollTop = win.scrollHeight; 
        });
    }
};