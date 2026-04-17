document.addEventListener('DOMContentLoaded', () => {

    const tabScan = document.getElementById('tab-scan');
    const tabWhitelist = document.getElementById('tab-whitelist');
    const viewScan = document.getElementById('view-scan');
    const viewWhitelist = document.getElementById('view-whitelist');

    const scanBtn = document.getElementById('scan_btn');
    const detailsToggle = document.getElementById('details-toggle');
    const detailsPanel = document.getElementById('details-panel');

    const settingsBtn = document.getElementById('settings-btn');
    if (settingsBtn) {
        settingsBtn.addEventListener('click', () => {

            if (chrome.runtime.openOptionsPage) {
                chrome.runtime.openOptionsPage();
            } else {
                window.open(chrome.runtime.getURL('options.html'));
            }
        });
    }

    tabScan.addEventListener('click', () => {
        tabScan.classList.add('active');
        tabWhitelist.classList.remove('active');
        viewScan.classList.remove('hidden');
        viewWhitelist.classList.add('hidden');
        applyWhitelistStateIfWhitelisted();
    });

    tabWhitelist.addEventListener('click', () => {
        tabWhitelist.classList.add('active');
        tabScan.classList.remove('active');
        viewWhitelist.classList.remove('hidden');
        viewScan.classList.add('hidden');
        renderWhitelist();
    });
    let currentDomain = "unknown-website.com";

    function applyWhitelistStateIfWhitelisted() {
        let whitelist = JSON.parse(localStorage.getItem('crainte_whitelist')) || [];
        if (whitelist.includes(currentDomain)) {
            setUIState('safe', 'Whitelisted', 'This domain is on your trusted list. Scanning is disabled.');
            detailsToggle.classList.add('hidden');
            detailsPanel.classList.add('hidden');
            scanBtn.classList.add('hidden');
            return true;
        } else {
            setUIState('neutral', 'Ready to use', 'Click "SCAN WEBSITE" to start the scanning.');
            scanBtn.classList.remove('hidden');
            scanBtn.disabled = false;
            scanBtn.textContent = "SCAN WEBSITE";
            return false;
        }
    }

    if (typeof chrome !== 'undefined' && chrome.tabs) {
        chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
            if (tabs[0] && tabs[0].url) {
                try {
                    const url = new URL(tabs[0].url);
                    currentDomain = url.hostname.toLowerCase().replace(/^www\./, '');
                    document.getElementById('current-url').innerHTML = `<b>${currentDomain}</b>`;
                    applyWhitelistStateIfWhitelisted();
                } catch (e) { }
            }
        });
    }

    scanBtn.addEventListener('click', async () => {
        if (applyWhitelistStateIfWhitelisted()) return;

        const keys = await chrome.storage.local.get(['groqKey', 'vtKey']);

        if (!keys.groqKey || !keys.vtKey) {
            setUIState('warning', 'Missing API Keys', 'Please click the ⚙️ gear icon in the top right to save your Groq and VirusTotal API keys.');
            scanBtn.classList.remove('hidden');
            return;
        }
        scanBtn.disabled = true;
        scanBtn.textContent = "ANALYZING...";
        setUIState('loading', 'Scanning...', 'Waiting for response from the server and Gemini AI model...');

        try {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

            const isSecure = tab.url.startsWith('https://');
            const isLocalHost = tab.url.startsWith('http://localhost') || tab.url.startsWith('http://127.0.0.1');

            let sslWarningMsg = "";
            if (!isSecure && !isLocalHost) {
                sslWarningMsg = "NO SSL DETECTED: Connection is unencrypted. ";
            }

            const cleanUrl = tab.url.split('?')[0].split('#')[0];
            const cacheKey = `scan_${cleanUrl}`

            const cacheRecord = await chrome.storage.local.get(cacheKey);

            if (!tab.url || tab.url.startsWith('chrome://') || tab.url.startsWith('edge://')) {
                setUIState('warning', 'Restricted Page', 'Cannot scan internal browser pages.');
                return;
            }



            if (cacheRecord[cacheKey]) {
                const savedData = cacheRecord[cacheKey];
                const ageInMs = Date.now() - savedData.timestamp;
                const twentyFourHoursInMs = 24 * 60 * 60 * 1000;

                if (ageInMs < twentyFourHoursInMs) {
                    console.log("CACHE HIT: Loaded from local storage. API saved.");

                    if (!savedData.result.summary.startsWith("[Cached]")) {
                        savedData.result.summary = "[Cached]\n\n" + savedData.result.summary;
                    }
                    if (savedData.result.ssl_secure === undefined) {
                        savedData.result.ssl_secure = (isSecure || isLocalHost);
                    }

                    updateUIWithScanData(savedData.result);

                    return;
                } else {
                    console.log("CACHE EXPIRED: Fetching fresh data.");
                    await chrome.storage.local.remove(cacheKey);
                }
            }

            console.log("CACHE MISS: Initiating full scan.");
            const injectionResults = await chrome.scripting.executeScript({
                target: { tabId: tab.id },
                func: scrapePageData,
            });

            const scrapedData = injectionResults[0].result;

            if (!scrapedData || !scrapedData.text) {
                setUIState('warning', 'Error', 'Could not read text from this page.');
                return;
            }

            const googleScriptUrl = "https://script.google.com/macros/s/AKfycbzlPNEss098PekSn8d1G5cjTL2z-5g8YAlqye8ZB-ZErLSV7sdif-EXnsBcP3_SOpmctg/exec";

            const payload = {
                token: "TheSunIsPurpleIsIt!",
                url: scrapedData.url,
                text: scrapedData.text,
                groqKey: keys.groqKey,
                vtKey: keys.vtKey
            };

            const response = await fetch(googleScriptUrl, {
                method: "POST",
                headers: { "Content-Type": "text/plain;charset=utf-8" },
                body: JSON.stringify(payload)
            });

            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);

            const data = await response.json();
            console.log("GAS Backend Replied:", data);

            data.ssl_secure = (isSecure || isLocalHost);
            if (!isSecure && !isLocalHost) {
                if (data.risk_level === "safe") {
                    data.risk_level = "warning";
                    data.title = "Unencrypted Connection";
                    data.reason = sslWarningMsg + data.reason;
                } else if (!data.reason.includes(sslWarningMsg)) {
                    data.reason = sslWarningMsg + data.reason;
                }
            }

            updateUIWithScanData(data);

            if (data.success) {
                const newCacheEntry = {};
                newCacheEntry[cacheKey] = {
                    timestamp: Date.now(),
                    result: data
                };
                await chrome.storage.local.set(newCacheEntry);
            }

        } catch (error) {
            setUIState('dangerous', 'Connection Failed', error.message);
        } finally {
            scanBtn.disabled = false;
            scanBtn.textContent = "SCAN WEBSITE";
        }
    });

    detailsToggle.addEventListener('click', () => {
        detailsPanel.classList.toggle('hidden');
        detailsToggle.textContent = detailsPanel.classList.contains('hidden') ? 'Show verification details ▼' : 'Hide details ▲';
    });

    function setUIState(type, title, reason) {
        document.getElementById('status-title').textContent = title;
        document.getElementById('status-title').className = `text-${type}`;
        document.getElementById('ai-reason').textContent = reason;

        const statusCircle = document.getElementById('status-circle');
        const iconSvg = document.getElementById('icon-svg');

        if (statusCircle && iconSvg) {
            statusCircle.className = 'status-circle-wrapper';

            if (type === 'loading' || type === 'neutral') {
                if (type === 'loading') statusCircle.classList.add('loading');
                iconSvg.innerHTML = '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>';
            } else {
                statusCircle.classList.add(type);
                if (type === 'safe') {
                    iconSvg.innerHTML = '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><path d="M9 12l2 2 4-4" stroke-width="3"></path>';
                } else if (type === 'warning') {
                    iconSvg.innerHTML = '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line>';
                } else if (type === 'dangerous') {
                    iconSvg.innerHTML = '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><line x1="9" y1="9" x2="15" y2="15"></line><line x1="15" y1="9" x2="9" y2="15"></line>';
                }
            }
        }
    }

    function updateUIWithScanData(data) {
        document.getElementById('vt-score').textContent = data.vt_score || "Error";
        document.getElementById('whois-score').textContent = data.domain_age || "Error";

        let sslScoreEl = document.getElementById('ssl-score');
        if (sslScoreEl && data.ssl_secure !== undefined) {
            sslScoreEl.textContent = data.ssl_secure ? "Yes" : "No";
            sslScoreEl.style.color = data.ssl_secure ? "var(--safe)" : "var(--danger)";
        }

        scanBtn.classList.add('hidden');
        detailsToggle.classList.remove('hidden');

        const combinedText = data.reason + "\n\nSummary:\n" + data.summary;
        setUIState(data.risk_level, data.title, combinedText);

        const aiArrowEl = document.getElementById('gauge-arrow');
        const aiScoreTextEl = document.getElementById('ai-score-text');
        if (aiScoreTextEl) aiScoreTextEl.textContent = data.title;

        if (aiArrowEl && aiScoreTextEl) {
            if (data.risk_level === 'safe') {
                aiScoreTextEl.style.color = '#27ae60';
                aiArrowEl.style.left = '16.6%';
                aiArrowEl.style.color = '#27ae60';
            } else if (data.risk_level === 'warning') {
                aiScoreTextEl.style.color = '#f39c12';
                aiArrowEl.style.left = '50%';
                aiArrowEl.style.color = '#f39c12';
            } else {
                aiScoreTextEl.style.color = '#e74c3c';
                aiArrowEl.style.left = '83.3%';
                aiArrowEl.style.color = '#e74c3c';
            }
        }
    }

    const whitelistInput = document.getElementById('whitelist-input');
    const whitelistAddBtn = document.getElementById('whitelist-add-btn');
    const whitelistUl = document.getElementById('whitelist-items');

    function renderWhitelist() {
        whitelistUl.innerHTML = '';
        let whitelist = JSON.parse(localStorage.getItem('crainte_whitelist')) || [];

        if (whitelist.length === 0) {
            whitelistUl.innerHTML = '<li style="justify-content:center; color:#95a5a6;">No trusted websites</li>';
            return;
        }

        whitelist.forEach(domain => {
            const li = document.createElement('li');
            li.textContent = domain;

            const delBtn = document.createElement('button');
            delBtn.textContent = 'Remove';
            delBtn.className = 'delete-btn';
            delBtn.onclick = () => removeDomain(domain);

            li.appendChild(delBtn);
            whitelistUl.appendChild(li);
        });
    }

    function addDomain() {
        let inputVal = whitelistInput.value.trim().toLowerCase();
        if (!inputVal) return;

        let domainToSave = inputVal;
        try {
            if (inputVal.startsWith('http')) {
                const url = new URL(inputVal);
                domainToSave = url.hostname.replace(/^www\./, '');
            } else {
                const url = new URL('https://' + inputVal);
                domainToSave = url.hostname.replace(/^www\./, '');
            }
        } catch (e) {
            domainToSave = inputVal.replace(/^www\./, '');
        }

        let whitelist = JSON.parse(localStorage.getItem('crainte_whitelist')) || [];
        if (!whitelist.includes(domainToSave)) {
            whitelist.push(domainToSave);
            localStorage.setItem('crainte_whitelist', JSON.stringify(whitelist));
        }
        whitelistInput.value = '';
        renderWhitelist();
    }

    function removeDomain(domain) {
        let whitelist = JSON.parse(localStorage.getItem('crainte_whitelist')) || [];
        whitelist = whitelist.filter(d => d !== domain);
        localStorage.setItem('crainte_whitelist', JSON.stringify(whitelist));
        renderWhitelist();
    }

    whitelistAddBtn.addEventListener('click', addDomain);
});

function scrapePageData() {
    const currentUrl = window.location.href;
    let pageText = document.body.innerText;
    pageText = pageText.replace(/\s+/g, ' ').trim().substring(0, 10000);
    return { url: currentUrl, text: pageText };
}