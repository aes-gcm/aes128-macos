import {Events, Window} from "@wailsio/runtime";
import {VPNService} from "../bindings/aes128";
import worldMapUrl from './assets/images/world-map.svg';
import binImageUrl from './assets/images/bin.png';
import settingsNotifyImageUrl from './assets/images/settings-notify.png';
import settingsImageUrl from './assets/images/settings.png';
import signalGoodUrl from './assets/images/signal_good.png';
import signalMediumUrl from './assets/images/signal_medium.png';
import signalBadUrl from './assets/images/signal_bad.png';
import lightningUrl from './assets/images/lightning.png';

document.addEventListener('DOMContentLoaded', () => {
    const appLayout = document.querySelector('.app-layout');
    const container = document.querySelector('.container');
    const minimizeBtn = document.getElementById('minimize-btn');
    const closeBtn = document.getElementById('close-btn');

    const panels = {
        login: document.getElementById('login-panel'),
        sessions: document.getElementById('sessions-panel'),
        app: document.getElementById('main-control-panel'),
    };

    const contentViews = {
        main: document.getElementById('main-app-content'),
        settings: document.getElementById('settings-content'),
        locations: document.getElementById('locations-content'),
        customLink: document.getElementById('custom-link-content'),
        splitTunnel: document.getElementById('split-tunnel-content'),
    };

    const mainControlPanel = document.getElementById('main-control-panel');
    const loginForm = document.getElementById('login-form');
    const loginBtn = loginForm.querySelector('button[type="submit"]');
    const loginUsernameInput = document.getElementById('login-username');
    const loginPasswordInput = document.getElementById('login-password');
    const loginErrorBox = document.getElementById('login-error-box');
    const goToRegisterLink = document.getElementById('go-to-register');

    const connectToggle = document.getElementById('connect-toggle');
    const statusText = document.getElementById('connection-status-text');
    const mapContainer = document.getElementById('map-svg-container');
    const serverSelectRow = document.getElementById('server-select-row');
    const selectedServerName = document.getElementById('selected-server-name');
    const protocolSelect = document.getElementById('protocol-select');
    const torExitToggle = document.getElementById('tor-exit-toggle');

    const settingsBtn = document.getElementById('settings-btn');
    const backToAppBtn = document.getElementById('back-to-app-btn');
    const logoutBtn = document.getElementById('logout-btn');
    const retryLoginBtn = document.getElementById('retry-login-btn');

    const updateNotifyDot = document.getElementById('update-notify-dot');
    const updateInfoBlock = document.getElementById('update-info-block');
    const downloadUpdateLink = document.getElementById('download-update-link');
    const latestVersionSpan = document.getElementById('latest-version-span');
    const currentVersionSpan = document.getElementById('current-version-span');

    const versionInfoBlock = document.getElementById('version-info-block');
    const footerCurrentVersionSpan = document.getElementById('footer-current-version-span');
    const versionClickTarget = document.getElementById('version-click-target');

    const miniModeToggle = document.getElementById('mini-mode-toggle');

    const customLinkToggle = document.getElementById('custom-link-toggle');
    const customLinkInput = document.getElementById('custom-link-input');
    const customLinkInputWrapper = document.getElementById('custom-link-input-wrapper');

    const goToSplitTunnel = document.getElementById('go-to-split-tunnel');
    const splitTunnelToggle = document.getElementById('split-tunnel-toggle');
    const splitTunnelDiscord = document.getElementById('split-tunnel-discord');
    const splitTunnelDiscordLabel = splitTunnelDiscord.closest('.st-preset-tag');
    const splitTunnelSteam = document.getElementById('split-tunnel-steam');
    const splitTunnelSteamLabel = splitTunnelSteam.closest('.st-preset-tag');
    const splitTunnelCustom = document.getElementById('split-tunnel-custom');
    const splitTunnelLoadFileBtn = document.getElementById('split-tunnel-load-file');
    const splitTunnelModeSelect = document.getElementById('st-mode-select');
    const domainValidationError = document.getElementById('domain-validation-error');

    const autostartToggle = document.getElementById('autostart-toggle');
    const autoconnectToggle = document.getElementById('autoconnect-toggle');
    const confirmModal = document.getElementById('custom-confirm-modal');
    const confirmTitle = document.getElementById('confirm-title');
    const confirmMessage = document.getElementById('confirm-message');
    const confirmYesBtn = document.getElementById('confirm-yes-btn');
    const confirmNoBtn = document.getElementById('confirm-no-btn');

    const PING_CACHE_KEY = 'aes128-ping-cache';
    const CACHE_DURATION_MS = 10 * 60 * 1000;

    let appData = {};
    let lastLoginAttempt = {};
    let isConnecting = false;
    let connectingAnimationInterval = null;
    let sessionValidationInterval = null;
    let versionClickCount = 0;
    let connectionGeneration = 0;
    let savedIPBeforeConnect = '';

    let saveQueue = Promise.resolve();
    let saveTimer = null;
    async function saveAppData(strict = false) {
        clearTimeout(saveTimer);
        try {
            appData.splitTunnelDomains = buildSplitTunnelDomainString();
            const snapshot = JSON.stringify(appData);
            saveQueue = saveQueue.catch(() => {}).then(() => VPNService.SaveAppData(snapshot));
            await saveQueue;
        } catch (e) {
            console.error("Go backend failed to save app data:", e);
            if (strict) throw e;
        }
    }
    function scheduleSave() {
        clearTimeout(saveTimer);
        saveTimer = setTimeout(() => saveAppData(), 300);
    }

    function isValidDomainSuffix(domain) {
        if (typeof domain !== 'string' || domain.length === 0) { return false; }
        if (!domain.includes('.')) { return false; }
        if (domain.startsWith('.') || domain.endsWith('.')) { return false; }
        if (/[ ,/\\:?*!"<>|]/.test(domain)) { return false; }
        if (domain.trim() !== domain) { return false; }
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) { return false; }
        return true;
    }

    function validateCustomDomains() {
        const domains = (appData.splitTunnelCustom || '').split(',')
            .map(d => d.trim())
            .filter(d => d.length > 0);
        const invalidDomains = domains.filter(d => !isValidDomainSuffix(d));
        if (invalidDomains.length > 0) {
            domainValidationError.textContent = `Invalid: ${invalidDomains.join(', ')}`;
            domainValidationError.classList.add('is-visible');
            return false;
        } else {
            domainValidationError.classList.remove('is-visible');
            domainValidationError.textContent = '';
            return true;
        }
    }

    function buildSplitTunnelDomainString() {
        if (!appData.splitTunnelEnabled) { return ""; }
        const domains = new Set();
        const customDomains = (appData.splitTunnelCustom || '').split(',')
            .map(d => d.trim())
            .filter(d => d.length > 0);
        const validCustomDomains = customDomains.filter(isValidDomainSuffix);
        if (appData.splitTunnelDiscord) { ['discord.com', 'discordapp.com', 'discord.gg', 'cdn.discordapp.com', 'discordcdn.com', 'discord.media', 'discordstatus.com', 'dis.gd', 'discordapp.net'].forEach(d => domains.add(d)); }
        if (appData.splitTunnelSteam) { ['steampowered.com', 'store.steampowered.com', 'steamcommunity.com', 'steamstatic.com', 'steamcontent.com', 'steamusercontent.com', 'steamserver.net', 'steamgames.com', 'steamdeck.com'].forEach(d => domains.add(d)); }
        validCustomDomains.forEach(d => domains.add(d));
        return Array.from(domains).join(',');
    }

    async function loadAppData() {
        const defaults = {
            protocol: 'vless-xhttp',
            isMini: false,
            enableTor: false,
            useCustomLink: false,
            customV2rayLink: '',
            selectedLocationName: 'Fastest server',
            splitTunnelEnabled: false,
            splitTunnelDiscord: false,
            splitTunnelSteam: false,
            splitTunnelCustom: '',
            splitTunnelMode: 'exclude',
            autoStart: false,
            autoConnect: false,
        };
        try {
            const appDataJson = await VPNService.LoadAppData();
            const loaded = JSON.parse(appDataJson);
            appData = { ...defaults, ...loaded };
        } catch (e) {
            console.error("Failed to load app data from Go, using defaults:", e);
            appData = { ...defaults };
        }
    }

    function applySettingsToUI() {
        protocolSelect.value = appData.protocol || 'vless-xhttp';
        miniModeToggle.checked = appData.isMini || false;
        torExitToggle.checked = appData.enableTor || false;
        customLinkToggle.checked = appData.useCustomLink || false;
        customLinkInput.value = appData.customV2rayLink || '';
        customLinkInputWrapper.style.display = appData.useCustomLink ? 'block' : 'none';
        splitTunnelToggle.checked = appData.splitTunnelEnabled || false;
        splitTunnelDiscord.checked = appData.splitTunnelDiscord || false;
        splitTunnelDiscordLabel.classList.toggle('checked', appData.splitTunnelDiscord);
        splitTunnelSteam.checked = appData.splitTunnelSteam || false;
        splitTunnelSteamLabel.classList.toggle('checked', appData.splitTunnelSteam);
        splitTunnelCustom.value = appData.splitTunnelCustom || '';
        splitTunnelModeSelect.value = appData.splitTunnelMode || 'exclude';
        serverSelectRow.classList.toggle('disabled', appData.useCustomLink || false);
        if (appData.useCustomLink) { selectedServerName.textContent = 'Custom server'; }
        else { selectedServerName.textContent = appData.selectedLocationName || 'Fastest server'; }
        container.classList.toggle('mini-mode', appData.isMini || false);

        autostartToggle.checked = appData.autoStart || false;
        autoconnectToggle.checked = appData.autoConnect || false;
    }

    function showPanel(panelName) {
        const mini = panelName === 'app' && Boolean(appData.isMini);
        container.classList.toggle('mini-mode', mini);
        VPNService.SetMiniMode(mini).catch(console.error);
        if (panelName === 'login' || panelName === 'sessions') { appLayout.classList.add('layout-fullscreen'); }
        else { appLayout.classList.remove('layout-fullscreen'); }
        Object.values(panels).forEach(panel => { if (panel) panel.classList.remove('active'); });
        if (panels[panelName]) { panels[panelName].classList.add('active'); }
        showContent('main');
    }

    function showContent(viewName) {
        mainControlPanel.classList.toggle('menu-visible', viewName !== 'main');
        Object.entries(contentViews).forEach(([name, view]) => { if(view) { view.classList.toggle('active', name === viewName); view.inert = name !== viewName; } });
        if (viewName === 'splitTunnel') { validateCustomDomains(); }
    }

    function showConfirmationModal(title, message) {
        return new Promise(resolve => {
            confirmTitle.textContent = title; confirmMessage.textContent = message; confirmModal.style.display = 'flex';
            const handleYes = () => { confirmModal.style.display = 'none'; confirmNoBtn.removeEventListener('click', handleNo); resolve(true); };
            const handleNo = () => { confirmModal.style.display = 'none'; confirmYesBtn.removeEventListener('click', handleYes); resolve(false); };
            confirmYesBtn.addEventListener('click', handleYes, { once: true }); confirmNoBtn.addEventListener('click', handleNo, { once: true });
        });
    }

    function animateViewBox(svg, target, duration, onEnd) {
        if (!svg) return;
        const startViewBox = svg.getAttribute('viewBox').split(' ').map(Number);
        const [startX, startY, startWidth, startHeight] = startViewBox;
        const [targetX, targetY, targetWidth, targetHeight] = target;
        let startTime = null;
        const easeInOutCubic = t => t < 0.5 ? 4 * t * t * t : (t - 1) * (2 * t - 2) * (2 * t - 2) + 1;
        function step(timestamp) {
            if (!startTime) startTime = timestamp;
            const progress = Math.min((timestamp - startTime) / duration, 1);
            const easedProgress = easeInOutCubic(progress);
            const currentX = startX + (targetX - startX) * easedProgress; const currentY = startY + (targetY - startY) * easedProgress;
            const currentWidth = startWidth + (targetWidth - startWidth) * easedProgress; const currentHeight = startHeight + (targetHeight - startHeight) * easedProgress;
            svg.setAttribute('viewBox', `${currentX} ${currentY} ${currentWidth} ${currentHeight}`);
            if (progress < 1) { window.requestAnimationFrame(step); } else { if (onEnd) onEnd(); }
        }
        window.requestAnimationFrame(step);
    }

    function setupMap(ipInfo) {
        const svg = mapContainer.querySelector('svg');
        if (!svg) {
            fetch(worldMapUrl).then(response => response.text()).then(svgData => {
                mapContainer.innerHTML = svgData; const newSvg = mapContainer.querySelector('svg');
                if (newSvg) { newSvg.setAttribute('viewBox', `700 100 500 200`); updateMapForIp(newSvg, ipInfo); }
            });
        } else { updateMapForIp(svg, ipInfo); }
    }

    function updateMapForIp(svg, ipInfo) {
        svg.querySelectorAll('.country-active').forEach(p => p.classList.remove('country-active'));
        if (!ipInfo || !ipInfo.countryCode) return;
        const countryPath = svg.getElementById(ipInfo.countryCode) || svg.getElementById('US');
        if (!countryPath) return;
        const allPaths = Array.from(svg.querySelectorAll(`#${countryPath.id}`));
        allPaths.forEach(path => path.classList.add('country-active'));
        let totalBBox = allPaths.reduce((acc, path) => {
            const pathBBox = path.getBBox(); if (!acc) return pathBBox;
            const minX = Math.min(acc.x, pathBBox.x); const minY = Math.min(acc.y, pathBBox.y);
            const maxX = Math.max(acc.x + acc.width, pathBBox.x + pathBBox.width); const maxY = Math.max(acc.y + acc.height, pathBBox.y + pathBBox.height);
            return { x: minX, y: minY, width: maxX - minX, height: maxY - minY };
        }, null);
        if (!totalBBox || totalBBox.width <= 0 || totalBBox.height <= 0 || !isFinite(totalBBox.width) || !isFinite(totalBBox.height)) { return; }
        const bbox = totalBBox; const centerX = bbox.x + bbox.width / 2; const centerY = bbox.y + bbox.height / 2;
        const countryArea = bbox.width * bbox.height; const baseScale = 2000; const scaleFactor = Math.sqrt(countryArea);
        const maxZoomOutWidth = 800; const calculatedWidth = baseScale / Math.max(1, 250 / scaleFactor);
        const newWidth = Math.min(maxZoomOutWidth, calculatedWidth); const newHeight = newWidth / 2;
        const newX = centerX - newWidth / 2; const newY = centerY - newHeight / 2;
        const targetViewBox = [newX, newY, newWidth, newHeight]; animateViewBox(svg, targetViewBox, 2000, null);
    }

    function stopConnectingAnimation() { if (connectingAnimationInterval) { clearInterval(connectingAnimationInterval); connectingAnimationInterval = null; } }

    function startConnectingAnimation() {
        stopConnectingAnimation(); statusText.style.fontSize = ''; statusText.textContent = 'connecting..';
        statusText.classList.add('connecting'); statusText.classList.remove('connected', 'danger');

        let dots = 2; connectingAnimationInterval = setInterval(() => { dots = dots === 2 ? 3 : 2; statusText.textContent = 'connecting' + '.'.repeat(dots); }, 500);
    }
    const locationCountryCodes = {
        'amsterdam': 'NL', 'nl': 'NL', 'netherlands': 'NL',
        'frankfurt': 'DE', 'de': 'DE', 'germany': 'DE', 'berlin': 'DE', 'munich': 'DE',
        'warsaw': 'PL', 'pl': 'PL', 'poland': 'PL',
        'london': 'GB', 'uk': 'GB', 'gb': 'GB',
        'paris': 'FR', 'fr': 'FR', 'france': 'FR',
        'helsinki': 'FI', 'fi': 'FI', 'finland': 'FI',
        'vilnius': 'LT', 'lt': 'LT', 'lithuania': 'LT',
        'riga': 'LV', 'lv': 'LV', 'latvia': 'LV',
        'tallinn': 'EE', 'ee': 'EE', 'estonia': 'EE',
        'stockholm': 'SE', 'se': 'SE', 'sweden': 'SE',
        'oslo': 'NO', 'no': 'NO', 'norway': 'NO',
        'copenhagen': 'DK', 'dk': 'DK', 'denmark': 'DK',
        'zurich': 'CH', 'ch': 'CH', 'switzerland': 'CH',
        'vienna': 'AT', 'at': 'AT', 'austria': 'AT',
        'prague': 'CZ', 'cz': 'CZ', 'czech': 'CZ',
        'bucharest': 'RO', 'ro': 'RO', 'romania': 'RO',
        'sofia': 'BG', 'bg': 'BG', 'bulgaria': 'BG',
        'madrid': 'ES', 'es': 'ES', 'spain': 'ES',
        'lisbon': 'PT', 'pt': 'PT', 'portugal': 'PT',
        'rome': 'IT', 'it': 'IT', 'italy': 'IT', 'milan': 'IT',
        'new york': 'US', 'us': 'US', 'usa': 'US', 'los angeles': 'US', 'miami': 'US', 'chicago': 'US', 'dallas': 'US',
        'toronto': 'CA', 'ca': 'CA', 'canada': 'CA', 'montreal': 'CA',
        'tokyo': 'JP', 'jp': 'JP', 'japan': 'JP',
        'singapore': 'SG', 'sg': 'SG',
        'sydney': 'AU', 'au': 'AU', 'australia': 'AU',
    };

    function guessCountryFromLocationName(locName) {
        if (!locName) return null;
        const lower = locName.toLowerCase();
        for (const [key, code] of Object.entries(locationCountryCodes)) {
            if (lower.includes(key)) return code;
        }
        return null;
    }

    function updateIPDisplay(ipInfo) {
        if (!ipInfo || !ipInfo.query) return;
        document.getElementById('ip-info-address').textContent = ipInfo.query;

        let city = ipInfo.city;
        let country = ipInfo.country;
        let countryCode = ipInfo.countryCode;
        if ((!city || city === 'Unknown') && appData.selectedLocationName && appData.selectedLocationName !== 'Fastest server') {
            city = appData.selectedLocationName;
            const guessedCode = guessCountryFromLocationName(appData.selectedLocationName);
            if (guessedCode) {
                countryCode = guessedCode;
                if (!country || country === 'Unknown') country = guessedCode;
            }
        }

        document.getElementById('ip-info-location').textContent = `${city || 'Unknown'}, ${country || 'Unknown'}`;
        setupMap({ ...ipInfo, city, country, countryCode });
    }

    function setDisconnectedState() {
        statusText.classList.remove('unverified');
        statusText.style.fontSize = '';
        statusText.textContent = 'disconnected';
        statusText.classList.remove('connected', 'connecting', 'danger');
        connectToggle.checked = false;
        isConnecting = false;

        Events.Emit("app:status", "disconnected");
    }

    function setConnectedState() {
        statusText.classList.remove('unverified');
        statusText.style.fontSize = '';
        statusText.textContent = 'connected';
        statusText.classList.remove('connecting', 'danger');
        statusText.classList.add('connected');
        isConnecting = false;

        Events.Emit("app:status", "connected");
    }

    function setErrorState(msg) {
        statusText.classList.remove('unverified');
        statusText.style.fontSize = '1.2rem';
        statusText.textContent = msg;
        statusText.classList.remove('connecting', 'connected');
        statusText.classList.add('danger');
        connectToggle.checked = false;
        isConnecting = false;

        Events.Emit("app:status", "disconnected");
    }
    async function waitForVPNConnection(oldIP, gen) {
        try {
            const result = await VPNService.WaitForConnection(oldIP);
            if (gen !== connectionGeneration) {
                return;
            }

            stopConnectingAnimation();

            if (result.connected) {
                setConnectedState();
                if (result.message === 'IP not verified') {
                    statusText.textContent = 'IP not verified'; statusText.style.fontSize = '1.2rem';
                    statusText.classList.remove('connected'); statusText.classList.add('unverified');
                }
                if (result.ipInfo && result.ipInfo.query) {
                    updateIPDisplay(result.ipInfo);
                } else {
                    const locName = appData.selectedLocationName || '';
                    const cc = guessCountryFromLocationName(locName);
                    document.getElementById('ip-info-location').textContent = locName || 'Connected';
                    if (cc) {
                        setupMap({ countryCode: cc });
                    }
                }
            } else {
                setErrorState(result.message || 'Connection failed');
            }
        } catch (e) {
            if (gen !== connectionGeneration) return;
            console.error("WaitForConnection failed:", e);
            stopConnectingAnimation();
            setErrorState(String(e));
        }
    }

    async function renderLocationsList(pingResults) {
        const listEl = document.getElementById('locations-list'); listEl.innerHTML = '';
        const fastestItem = document.createElement('div'); fastestItem.className = 'location-item'; if (appData.selectedLocationName === 'Fastest server') { fastestItem.classList.add('selected'); }
        fastestItem.innerHTML = `<img src="${lightningUrl}" class="location-signal-icon" alt="Fastest"><span class="location-name">Fastest server</span>`;
        fastestItem.addEventListener('click', () => { appData.selectedLocationName = 'Fastest server'; selectedServerName.textContent = 'Fastest server'; saveAppData(); showContent('main'); }); listEl.appendChild(fastestItem);
        const separator = document.createElement('div'); separator.className = 'location-separator'; separator.textContent = '[ALL LOCATIONS]'; listEl.appendChild(separator);
        const getRank = (rtt) => { if (rtt === -1 || rtt > 250) return 3; if (rtt > 100) return 2; return 1; };
        const sortedLocations = pingResults.map(loc => ({ ...loc, rank: getRank(loc.rttMillis) })).sort((a, b) => { if (a.rank < b.rank) return -1; if (a.rank > b.rank) return 1; return a.name.localeCompare(b.name); });
        sortedLocations.forEach(loc => {
            const item = document.createElement('div'); item.className = 'location-item'; if (appData.selectedLocationName === loc.name) { item.classList.add('selected'); }
            let signalIcon; if (loc.rank === 1) signalIcon = signalGoodUrl; else if (loc.rank === 2) signalIcon = signalMediumUrl; else signalIcon = signalBadUrl;
            item.innerHTML = `<img src="${signalIcon}" class="location-signal-icon" alt="Signal"><span class="location-name"></span>`;
            item.querySelector('.location-name').textContent = loc.name;
            item.addEventListener('click', () => { appData.selectedLocationName = loc.name; selectedServerName.textContent = loc.name; saveAppData(); showContent('main'); }); listEl.appendChild(item);
        });
    }

    async function fetchAndDisplayLocations(force = false) {
        const listEl = document.getElementById('locations-list');
        document.getElementById('location-search').value = '';
        const signature = `${appData.protocol}:${Boolean(appData.enableTor)}`;
        try { const cachedData = JSON.parse(localStorage.getItem(PING_CACHE_KEY)); if (!force && cachedData && cachedData.signature === signature && (Date.now() - cachedData.timestamp < CACHE_DURATION_MS)) { renderLocationsList(cachedData.results); return; } } catch (e) {}
        listEl.innerHTML = '<div class="location-item-loading">Pinging servers...</div>';
        try {
            const locationsWithPing = await VPNService.GetLocationsWithPing();
            localStorage.setItem(PING_CACHE_KEY, JSON.stringify({ timestamp: Date.now(), signature, results: locationsWithPing }));
            renderLocationsList(locationsWithPing);
        } catch (e) { listEl.textContent = String(e); }
    }

    function populateInfo(data) {
        if (!data) return;
        if(data.userData) { document.getElementById('main-username').textContent = data.userData.username || '-'; }
        if(data.sessionName) { document.getElementById('main-device-name').textContent = data.sessionName; }
        const currentVersion = data.appVersion || ''; if(currentVersion) { footerCurrentVersionSpan.textContent = currentVersion; currentVersionSpan.textContent = currentVersion; }
        const latestVersion = data.latestAppVersion || ''; if (latestVersion) { latestVersionSpan.textContent = latestVersion; }
        const updateBlock = document.querySelector('.settings-update');
        if (data.isUpdateAvailable) { settingsBtn.src = settingsNotifyImageUrl; if(updateBlock) updateBlock.classList.add('visible'); }
        else { settingsBtn.src = settingsImageUrl; if(updateBlock) updateBlock.classList.remove('visible'); }
        if (data.ipInfo) { document.getElementById('ip-info-address').textContent = data.ipInfo.query || 'N/A'; document.getElementById('ip-info-location').textContent = `${data.ipInfo.city || 'Unknown'}, ${data.ipInfo.country || 'Unknown'}`; setupMap(data.ipInfo); }
    }

    async function initializeApp() {
        try {
            const startupData = await VPNService.StartupCheck();
            appData = { ...startupData.initialAppData };
            applySettingsToUI();
            populateInfo(startupData);
            if (startupData.isLoggedIn) {
                appData = { ...appData, ...startupData.initialAppData };
                if (!appData.protocol || appData.protocol === 'trojan' || appData.protocol === 'vless') {
                    appData.protocol = 'vless-xhttp';
                }
                if (!appData.selectedLocationName) { appData.selectedLocationName = 'Fastest server'; }
                applySettingsToUI();
                populateInfo({ ...startupData, ...startupData.initialAppData });
                showPanel('app'); startSessionValidation();
                const coreStatus = JSON.parse(await VPNService.GetCoreStatus());
                connectToggle.checked = Boolean(coreStatus.isRunning);
                if (coreStatus.isRunning) setConnectedState();
                startCoreMonitoring();
                if (appData.autoConnect && !connectToggle.checked) {
                    setTimeout(() => { connectToggle.click(); }, 1000);
                }
            } else { showPanel('login'); setupMap(null); }
        } catch (error) { loginErrorBox.textContent = `Startup Error: ${error}`; loginErrorBox.classList.add('is-visible'); showPanel('login'); }
        finally { appLayout.classList.remove('loading'); }
    }

    let deletingSession = false;
    function renderSessionsList(sessions = []) {
        sessions = Array.isArray(sessions) ? sessions : [];
        const sessionsList = document.getElementById('sessions-list'); sessionsList.innerHTML = '';
        sessions.forEach(session => {
            const item = document.createElement('div'); item.className = 'session-item'; const name = document.createElement('span'); name.className = 'session-name'; name.textContent = session.name; const deleteBtn = document.createElement('img'); deleteBtn.src = binImageUrl; deleteBtn.className = 'delete-session-btn'; deleteBtn.alt = 'Delete session';
            deleteBtn.tabIndex = 0; deleteBtn.setAttribute('role', 'button');
            deleteBtn.setAttribute('aria-label', `Terminate ${session.name}`);
            deleteBtn.addEventListener('keydown', event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); deleteBtn.click(); } });
            deleteBtn.addEventListener('click', async () => {
                if (deletingSession) return;
                deletingSession = true; retryLoginBtn.disabled = true;
                const info = document.querySelector('.sessions-error-info');
                info.textContent = 'Terminating session...';
                try {
                    const { username, password } = lastLoginAttempt;
                    const result = await VPNService.DeleteSessionWithCredentials(username, password, session.id);
                    if (!result.success) throw new Error(result.error || 'Could not terminate session.');
                    renderSessionsList(result.sessions);
                    info.textContent = 'Session terminated. You can now log in.';
                } catch (error) { info.textContent = String(error.message || error); retryLoginBtn.disabled = sessions.length >= 3; }
                finally { deletingSession = false; }
            });
            item.appendChild(name); item.appendChild(deleteBtn); sessionsList.appendChild(item);
        });
        retryLoginBtn.disabled = sessions.length >= 3;
    }

    async function handleLoginResult(result) {
        if (result.success) {
            lastLoginAttempt = {}; loginPasswordInput.value = '';
            localStorage.removeItem(PING_CACHE_KEY);
            await initializeApp();
        }
        else if (result.sessions && result.sessions.length > 0) { renderSessionsList(result.sessions); showPanel('sessions'); }
        else { loginErrorBox.textContent = result.error || 'Unknown login error.'; loginErrorBox.classList.add('is-visible'); showPanel('login'); }
        loginBtn.disabled = false; loginBtn.textContent = 'Login';
    }

    async function handleInvalidSession() {
        connectionGeneration++;
        clearTimeout(saveTimer);
        await saveQueue.catch(() => {});
        lastLoginAttempt = {}; loginPasswordInput.value = '';
        localStorage.removeItem(PING_CACHE_KEY);
        stopSessionValidation();
        if (connectToggle.checked) {
            try { await VPNService.StopCore(); } catch (e) { console.error("StopCore during invalid session:", e); }
            connectToggle.checked = false;
            statusText.style.fontSize = ''; statusText.textContent = 'disconnected';
            statusText.classList.remove('connected', 'connecting', 'danger');
            Events.Emit("app:status", "disconnected");
        }
        stopConnectingAnimation();
        try { await VPNService.LogoutAndForget(); } catch (e) { console.error("LogoutAndForget error:", e); }
        showPanel('login');
    }

    function startSessionValidation() {
        stopSessionValidation();
        sessionValidationInterval = setInterval(async () => {
            try {
                const validationStatus = await VPNService.ValidateSession();
                if (validationStatus === "invalid") await handleInvalidSession();
            } catch (error) { console.error('Session check failed:', error); }
        }, 300000);
    }
    function stopSessionValidation() { if (sessionValidationInterval) { clearInterval(sessionValidationInterval); sessionValidationInterval = null; } }

    let coreMonitor = null;
    let coreCheckPending = false;
    function startCoreMonitoring() {
        clearInterval(coreMonitor);
        coreMonitor = setInterval(async () => {
            if (coreCheckPending || isConnecting || !connectToggle.checked) return;
            coreCheckPending = true;
            const generation = connectionGeneration;
            try {
                const status = JSON.parse(await VPNService.GetCoreStatus());
                if (generation === connectionGeneration && !isConnecting && !status.isRunning) {
                    setErrorState('Connection lost');
                    VPNService.GetMyIP().then(updateIPDisplay).catch(console.error);
                }
            } catch (error) { console.error('Core status check failed:', error); }
            finally { coreCheckPending = false; }
        }, 5000);
    }

    document.getElementById('toggle-password').addEventListener('click', event => {
        const visible = loginPasswordInput.type === 'password';
        loginPasswordInput.type = visible ? 'text' : 'password';
        event.currentTarget.textContent = visible ? 'HIDE' : 'SHOW';
        event.currentTarget.setAttribute('aria-label', visible ? 'Hide password' : 'Show password');
        event.currentTarget.setAttribute('aria-pressed', String(visible));
    });
    document.getElementById('cancel-sessions-btn').addEventListener('click', () => {
        if (deletingSession) return;
        lastLoginAttempt = {}; loginPasswordInput.value = ''; showPanel('login');
    });
    document.getElementById('location-search').addEventListener('input', event => {
        const query = event.target.value.trim().toLowerCase();
        document.querySelectorAll('#locations-list .location-item').forEach(item => {
            item.hidden = !item.querySelector('.location-name').textContent.toLowerCase().includes(query);
        });
    });
    document.getElementById('refresh-locations').addEventListener('click', async event => {
        const button = event.currentTarget; button.disabled = true;
        try { await fetchAndDisplayLocations(true); } finally { button.disabled = false; }
    });

    loginForm.addEventListener('submit', async (event) => {
        event.preventDefault(); if (loginBtn.disabled) return;
        loginErrorBox.classList.remove('is-visible'); loginBtn.disabled = true; loginBtn.textContent = 'Logging in...'; retryLoginBtn.disabled = true;
        const username = loginUsernameInput.value.trim(); const password = loginPasswordInput.value; lastLoginAttempt = { username, password };
        try { const result = await VPNService.Login(username, password); await handleLoginResult(result); }
        catch (error) { loginErrorBox.textContent = `Login Error: ${error}`; loginErrorBox.classList.add('is-visible'); loginBtn.disabled = false; loginBtn.textContent = 'Login'; }
    });
    retryLoginBtn.addEventListener('click', () => { if (!retryLoginBtn.disabled) { loginForm.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true })); } });
    goToRegisterLink.addEventListener('click', (event) => { event.preventDefault(); VPNService.BrowserOpenURL('https://aes.cx/en/account/register/'); });
    downloadUpdateLink.addEventListener('click', (event) => { event.preventDefault(); VPNService.BrowserOpenURL('https://aes.cx/en/app/download/macos/'); });
    settingsBtn.addEventListener('click', () => showContent('settings'));
    backToAppBtn.addEventListener('click', () => showContent('main'));
    serverSelectRow.addEventListener('click', () => { if (appData.useCustomLink) { return; } fetchAndDisplayLocations(); showContent('locations'); });

    logoutBtn.addEventListener('click', async () => {
        const confirmed = await showConfirmationModal("Log Out", "Are you sure?"); if (!confirmed) return;
        connectionGeneration++;
        clearTimeout(saveTimer);
        await saveQueue.catch(() => {});
        lastLoginAttempt = {};
        localStorage.removeItem(PING_CACHE_KEY);
        stopSessionValidation();
        if (connectToggle.checked) {
            try {
                await VPNService.StopCore(); connectToggle.checked = false;
                statusText.style.fontSize = ''; statusText.textContent = 'disconnected';
                statusText.classList.remove('connected', 'connecting', 'danger');
                Events.Emit("app:status", "disconnected");
            } catch (e) { console.error("Failed stop core on logout:", e); }
        }
        await VPNService.LogoutAndForget(); loginUsernameInput.value = ''; loginPasswordInput.value = ''; loginBtn.disabled = false; loginBtn.textContent = 'Login'; showPanel('login');
    });

    connectToggle.addEventListener('change', async (event) => {
        const requestGeneration = ++connectionGeneration;
        if (event.target.checked) {
            if (!validateCustomDomains()) { showContent('splitTunnel'); event.target.checked = false; return; }
            try { await saveAppData(true); }
            catch (e) { console.error("Failed save settings before connect:", e); setErrorState("Failed to save settings"); return; }
            if (requestGeneration !== connectionGeneration) return;

            try {
                const ipEl = document.getElementById('ip-info-address');
                const locEl = document.getElementById('ip-info-location');
                savedIPBeforeConnect = ipEl.textContent;
                const savedLocBeforeConnect = locEl.textContent;
                const oldIP = (savedIPBeforeConnect && savedIPBeforeConnect !== '...' && savedIPBeforeConnect !== 'N/A') ? savedIPBeforeConnect : '';
                const gen = requestGeneration;

                isConnecting = true;
                startConnectingAnimation();
                const svg = mapContainer.querySelector('svg');
                if (svg) { animateViewBox(svg, [200, 0, 1600, 800], 2000, null); }

                if (!appData.useCustomLink && appData.selectedLocationName === 'Fastest server') {
                    appData.selectedLocationName = await VPNService.FindFastestLocation();
                    selectedServerName.textContent = appData.selectedLocationName;
                    await saveAppData(true);
                }
                if (gen !== connectionGeneration) return;
                await VPNService.StartCore();
                if (gen !== connectionGeneration) return;
                waitForVPNConnection(oldIP, gen);

            } catch (e) {
                if (requestGeneration !== connectionGeneration) return;
                console.error("Failed start core:", e);
                stopConnectingAnimation();
                setErrorState(String(e));
            }
        } else {
            connectionGeneration++;
            stopConnectingAnimation();
            isConnecting = false;
            setDisconnectedState();

            try {
                await VPNService.StopCore();
            } catch (e) { console.error("Failed stop core:", e); }
            if (savedIPBeforeConnect && savedIPBeforeConnect !== '...' && savedIPBeforeConnect !== 'N/A') {
                document.getElementById('ip-info-address').textContent = savedIPBeforeConnect;
            }
            const svg = mapContainer.querySelector('svg');
            if (svg) { animateViewBox(svg, [700, 100, 500, 200], 1500, null); }
            VPNService.GetMyIP().then(newIpInfo => {
                if (newIpInfo && newIpInfo.query) {
                    updateIPDisplay(newIpInfo);
                }
            }).catch(() => {});
        }
    });

    protocolSelect.addEventListener('change', () => { appData.protocol = protocolSelect.value; appData.selectedLocationName = 'Fastest server'; applySettingsToUI(); saveAppData(); });
    torExitToggle.addEventListener('change', () => { appData.enableTor = torExitToggle.checked; appData.selectedLocationName = 'Fastest server'; applySettingsToUI(); saveAppData(); });
    miniModeToggle.addEventListener('change', () => { const isMini = miniModeToggle.checked; appData.isMini = isMini; VPNService.SetMiniMode(isMini); saveAppData(); });

    autostartToggle.addEventListener('change', async () => {
        appData.autoStart = autostartToggle.checked;
        try { await VPNService.SetAutoStart(appData.autoStart); } catch (e) { console.error("SetAutoStart:", e); }
        applySettingsToUI();
        saveAppData();
    });
    autoconnectToggle.addEventListener('change', () => { appData.autoConnect = autoconnectToggle.checked; saveAppData(); });

    versionClickTarget.addEventListener('click', () => { versionClickCount++; if (versionClickCount >= 9) { showContent('customLink'); versionClickCount = 0; } });
    customLinkToggle.addEventListener('change', () => { appData.useCustomLink = customLinkToggle.checked; applySettingsToUI(); saveAppData(); });
    customLinkInput.addEventListener('input', () => { appData.customV2rayLink = customLinkInput.value; scheduleSave(); });

    goToSplitTunnel.addEventListener('click', () => { showContent('splitTunnel'); });
    const settingsList = document.querySelector('.settings-list');
    if (settingsList) {
        settingsList.addEventListener('scroll', () => {
            const atBottom = settingsList.scrollHeight - settingsList.scrollTop - settingsList.clientHeight < 10;
            settingsList.classList.toggle('scrolled-bottom', atBottom);
        });
    }
    splitTunnelToggle.addEventListener('change', () => { appData.splitTunnelEnabled = splitTunnelToggle.checked; saveAppData(); });
    splitTunnelModeSelect.addEventListener('change', () => { appData.splitTunnelMode = splitTunnelModeSelect.value; saveAppData(); });
    splitTunnelDiscord.addEventListener('change', () => { appData.splitTunnelDiscord = splitTunnelDiscord.checked; splitTunnelDiscordLabel.classList.toggle('checked', appData.splitTunnelDiscord); saveAppData(); });
    splitTunnelSteam.addEventListener('change', () => { appData.splitTunnelSteam = splitTunnelSteam.checked; splitTunnelSteamLabel.classList.toggle('checked', appData.splitTunnelSteam); saveAppData(); });
    splitTunnelCustom.addEventListener('input', () => { appData.splitTunnelCustom = splitTunnelCustom.value; validateCustomDomains(); scheduleSave(); });
    splitTunnelLoadFileBtn.addEventListener('click', async () => {
        try {
            const fileContent = await VPNService.LoadFile(); if (fileContent) {
                const domainsFromFile = fileContent.split(/[\n,]+/).map(d => d.trim()).filter(d => d.length > 0);
                const existingDomains = (appData.splitTunnelCustom || '').split(',').map(d => d.trim()).filter(d => d.length > 0);
                const allDomains = new Set([...existingDomains, ...domainsFromFile]); const newValue = Array.from(allDomains).join(', ');
                splitTunnelCustom.value = newValue; appData.splitTunnelCustom = newValue; validateCustomDomains(); saveAppData();
            }
        } catch (e) { console.error("Failed to load file:", e); }
    });
    minimizeBtn.addEventListener('click', () => Window.Minimise());
    closeBtn.addEventListener('click', () => Window.Hide());
    Events.On("tray:toggle_connect", () => {
        connectToggle.click();
    });

    initializeApp();
});
