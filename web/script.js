// Global state
let indexData = { ips: [], timeline: [] };
let currentIp = null;
let charts = {};
let config = { dataPath: 'data' }; // Default

// Metrics configuration
const METRICS_CONFIG = [
    { key: 'up_days', label: 'Uptime (Days)', color: '#28a745' },
    { key: 'users', label: 'Active Users', color: '#f2c960' },
    { key: 'tasks', label: 'Tasks', color: '#0366d6' },
    { key: 'load', label: 'Load Average', multi: ['r1m', 'r5m', 'r15m'], colors: ['#6f42c1', '#d0b0ff', '#e0cffc'] },
    { key: 'cpu_thread', label: 'CPU Threads', color: '#6a737d' },
    { key: 'cpu_id', label: 'CPU Idle %', color: '#28a745' },
    { key: 'cpu_wa', label: 'CPU Wait %', color: '#d73a49' },
    { key: 'mem', label: 'Memory Usage (GB)', type: 'composed', total: 'mem_total', parts: ['mem_used', 'mem_free', 'mem_shared', 'mem_buff', 'mem_avail'] },
    { key: 'swap', label: 'Swap Usage (GB)', type: 'composed', total: 'swap_total', parts: ['swap_used', 'swap_free'] },
    { key: 'tmp', label: 'Tmp Usage (GB)', type: 'composed', total: 'tmp_total', parts: ['tmp_used', 'tmp_avail'] }
];

// Initialize
document.addEventListener('DOMContentLoaded', async () => {
    // Force hide loading initially to ensure clean state
    toggleLoading(false);

    try {
        await loadConfig();
        await initDashboard();
        setupEventListeners();
    } catch (e) {
        console.error('Fatal initialization error:', e);
        alert('Fatal Error: ' + e.message);
    }
});

async function loadConfig() {
    console.log('loadConfig started');
    try {
        const response = await fetch('config.json');
        console.log('config.json fetch status:', response.status);
        const loadedConfig = await response.json();
        console.log('config.json parsed:', loadedConfig);
        if (loadedConfig.dataPath) {
            config.dataPath = loadedConfig.dataPath.replace(/\/$/, ''); // Remove trailing slash
        }
    } catch (error) {
        console.warn('Could not load config.json, using default data path.', error);
    }
    console.log('loadConfig finished, dataPath:', config.dataPath);
}

async function initDashboard() {
    toggleLoading(true);
    const statusText = document.getElementById('status-text');
    statusText.textContent = 'Scanning directories...';
    statusText.style.color = 'var(--brand-blue)';

    try {
        // 1. Fetch root data directory
        const response = await fetch(`${config.dataPath}/`);
        if (!response.ok) throw new Error(`Failed to fetch root: ${response.status}`);

        const text = await response.text();

        // 2. Parse for Date directories (YYYYmmdd)
        const dateDirs = parseDirectoryListing(text, /^\d{8}\/?$/);

        let allFiles = [];

        // 3. Scan each Date directory for Time directories
        const chunks = chunkArray(dateDirs, 5);
        let processedCount = 0;

        for (const chunk of chunks) {
            statusText.textContent = `Scanning directories... (${processedCount}/${dateDirs.length})`;

            await Promise.all(chunk.map(async (dateDir) => {
                try {
                    const cleanDateDir = dateDir.replace(/\/$/, '');
                    const res = await fetch(`${config.dataPath}/${cleanDateDir}/`);
                    const html = await res.text();
                    const timeDirs = parseDirectoryListing(html, /^\d{6}\/?$/);

                    timeDirs.forEach(timeDir => {
                        const cleanTimeDir = timeDir.replace(/\/$/, '');
                        const path = `${cleanDateDir}/${cleanTimeDir}/host_stat.json`;
                        const year = cleanDateDir.substring(0, 4);
                        const month = cleanDateDir.substring(4, 6);
                        const day = cleanDateDir.substring(6, 8);
                        const hour = cleanTimeDir.substring(0, 2);
                        const min = cleanTimeDir.substring(2, 4);
                        const sec = cleanTimeDir.substring(4, 6);

                        allFiles.push({
                            path: path,
                            timestamp: `${year}-${month}-${day}T${hour}:${min}:${sec}`
                        });
                    });
                } catch (e) {
                    console.warn(`Failed to scan ${dateDir}`, e);
                }
            }));
            processedCount += chunk.length;
        }


        if (allFiles.length === 0) {
            throw new Error('No data files found');
        }

        // Sort by timestamp
        allFiles.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
        indexData.timeline = allFiles;

        // 4. Discover IPs from the latest file
        const latestFile = allFiles[allFiles.length - 1];
        const latestData = await fetch(`${config.dataPath}/${latestFile.path}`).then(r => r.json());
        indexData.ips = Object.keys(latestData);

        // Populate UI
        await populateIpSelect();

    } catch (error) {
        console.error('Error scanning directories:', error);
        if (statusText) {
            statusText.textContent = 'Scan failed: ' + error.message;
            statusText.style.color = 'var(--danger)';
        }
    } finally {
        toggleLoading(false);
    }
}

function toggleLoading(show) {
    const overlay = document.getElementById('loading-overlay');
    if (!overlay) return;

    if (show) {
        overlay.style.display = 'flex';
    } else {
        overlay.style.display = 'none';
    }
}

window.onerror = function (msg, url, lineNo, columnNo, error) {
    console.error('Global error:', msg, error);
    // Force hide loading on error
    const overlay = document.getElementById('loading-overlay');
    if (overlay) overlay.style.display = 'none';

    const statusText = document.getElementById('status-text');
    if (statusText) {
        statusText.textContent = 'Error: ' + msg;
        statusText.style.color = 'red';
    }
    return false;
};

function parseDirectoryListing(html, regex) {
    const parser = new DOMParser();
    const doc = parser.parseFromString(html, 'text/html');
    const links = Array.from(doc.querySelectorAll('a'));

    return links
        .map(a => a.getAttribute('href'))
        .filter(href => href && regex.test(href));
}

function chunkArray(array, size) {
    const result = [];
    for (let i = 0; i < array.length; i += size) {
        result.push(array.slice(i, i + size));
    }
    return result;
}

async function populateIpSelect() {
    const ipList = document.getElementById('ip-list');
    const ipInput = document.getElementById('ip-input');
    ipList.innerHTML = '';

    if (!indexData.ips || indexData.ips.length === 0) {
        // Handle empty case if needed
        return;
    }

    indexData.ips.forEach(ip => {
        const option = document.createElement('option');
        option.value = ip;
        ipList.appendChild(option);
    });

    // URL Filter Logic
    const urlParams = new URLSearchParams(window.location.search);
    const urlIp = urlParams.get('ip');

    if (urlIp && indexData.ips.includes(urlIp)) {
        currentIp = urlIp;
    } else {
        currentIp = indexData.ips[0];
    }

    ipInput.value = currentIp;

    // Set default date range
    setDefaultDateRange();

    // Load initial data
    await loadData();
}

function setupEventListeners() {
    const ipInput = document.getElementById('ip-input');

    // Use 'change' event for datalist selection
    ipInput.addEventListener('change', (e) => {
        const val = e.target.value;
        if (indexData.ips.includes(val)) {
            currentIp = val;
            // Update URL without reload
            const url = new URL(window.location);
            url.searchParams.set('ip', currentIp);
            window.history.pushState({}, '', url);

            loadData();
        }
    });

    // Optional: Add 'input' event if you want instant search feedback or validation




    document.getElementById('refresh-btn').addEventListener('click', () => {
        loadData();
    });
}

function setDefaultDateRange() {
    if (!indexData.timeline || indexData.timeline.length === 0) return;

    const lastTime = new Date(indexData.timeline[indexData.timeline.length - 1].timestamp);
    const firstTime = new Date(indexData.timeline[0].timestamp);

    // Default to last 7 days
    let startTime = new Date(lastTime);
    startTime.setDate(startTime.getDate() - 7);

    if (startTime < firstTime) startTime = firstTime;

    const format = (d) => {
        const pad = (n) => n.toString().padStart(2, '0');
        return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
    };

    document.getElementById('start-date').value = format(startTime);
    document.getElementById('end-date').value = format(lastTime);
}

async function scanDirectories() {
    toggleLoading(true);
    const statusText = document.getElementById('status-text');
    // ... rest of scanDirectories (start) ...
    statusText.textContent = 'Scanning directories...';
    statusText.style.color = 'var(--brand-blue)';

    try {
        // ...
        // (This part is handled by the previous replace_file_content, but we need to make sure the start of the function has toggleLoading(true))
        // Since we are replacing the middle chunk in previous call, we need to be careful.
        // Actually, let's just modify loadData to use toggleLoading and update host info.
        // scanDirectories modification was incomplete in previous thought, let's fix it here if needed or assume previous call handled the end.
        // Wait, the previous call replaced the END of scanDirectories. I need to replace the START of scanDirectories too?
        // No, I can just add toggleLoading(true) to the start of scanDirectories in a separate call or this one if I span enough lines.
        // Let's focus on loadData and processResults here.
    } catch (e) { }
}


async function loadData() {
    if (!currentIp) return;

    toggleLoading(true);

    try {
        const statusText = document.getElementById('status-text');
        statusText.textContent = 'Loading data...';
        statusText.style.color = 'var(--brand-blue)';

        const startDateInput = document.getElementById('start-date');
        const endDateInput = document.getElementById('end-date');

        if (!startDateInput || !endDateInput) {
            throw new Error('Date inputs not found');
        }

        const startDate = new Date(startDateInput.value);
        const endDate = new Date(endDateInput.value);

        // Filter timeline based on range
        const filesToFetch = indexData.timeline.filter(item => {
            const t = new Date(item.timestamp);
            return t >= startDate && t <= endDate;
        });

        document.getElementById('data-points').textContent = filesToFetch.length;

        // Fetch all files in parallel
        const promises = filesToFetch.map(item => fetch(`${config.dataPath}/${item.path}`).then(res => res.json()));

        const results = await Promise.all(promises);
        const timeSeriesData = processResults(results, filesToFetch);
        renderCharts(timeSeriesData);

        // Update Host Info Panel
        updateHostInfo(results);

        statusText.textContent = 'Ready';
        statusText.style.color = 'var(--success)';
        document.getElementById('last-updated-time').textContent = new Date().toLocaleTimeString();
        document.getElementById('dashboard-title').textContent = `Dashboard: ${currentIp}`;

    } catch (error) {
        console.error('Error fetching data:', error);
        const statusText = document.getElementById('status-text');
        if (statusText) {
            statusText.textContent = 'Error fetching data: ' + error.message;
            statusText.style.color = 'var(--danger)';
        }
    } finally {
        toggleLoading(false);
    }
}

function updateHostInfo(results) {
    const panel = document.getElementById('host-info-panel');
    const nameDisplay = document.getElementById('host-name-display');
    const groupsDisplay = document.getElementById('host-groups-display');

    if (results.length > 0) {
        // Use the last data point
        const lastResult = results[results.length - 1];
        const hostData = lastResult[currentIp];

        if (hostData) {
            panel.style.display = 'flex';
            panel.style.flexDirection = 'column';

            if (hostData.host_name && Array.isArray(hostData.host_name)) {
                nameDisplay.textContent = hostData.host_name.join(', ');
            } else {
                nameDisplay.textContent = '-';
            }

            if (hostData.groups && Array.isArray(hostData.groups)) {
                groupsDisplay.textContent = hostData.groups.join(', ');
            } else {
                groupsDisplay.textContent = '-';
            }
            return;
        }
    }

    // Hide or clear if no data
    nameDisplay.textContent = '-';
    groupsDisplay.textContent = '-';
}

function processResults(results, files) {
    const data = {
        labels: [],
        metrics: {}
    };

    // Initialize metric arrays
    METRICS_CONFIG.forEach(m => {
        if (m.type === 'composed') {
            data.metrics[m.total] = [];
            m.parts.forEach(p => data.metrics[p] = []);
        } else if (m.multi) {
            m.multi.forEach(sub => data.metrics[sub] = []);
        } else {
            data.metrics[m.key] = [];
        }
    });

    results.forEach((res, idx) => {
        const timestamp = new Date(files[idx].timestamp).toLocaleString();
        data.labels.push(timestamp);

        // Extract data for current IP
        const hostData = res[currentIp];

        if (hostData) {
            METRICS_CONFIG.forEach(m => {
                if (m.type === 'composed') {
                    data.metrics[m.total].push(hostData[m.total]);
                    m.parts.forEach(p => data.metrics[p].push(hostData[p]));
                } else if (m.multi) {
                    m.multi.forEach(sub => data.metrics[sub].push(hostData[sub]));
                } else {
                    data.metrics[m.key].push(hostData[m.key]);
                }
            });
        }
    });

    return data;
}

function renderCharts(data) {
    const container = document.getElementById('charts-container');
    container.innerHTML = '';
    charts = {};

    METRICS_CONFIG.forEach(config => {
        const card = document.createElement('div');
        card.className = 'chart-card';

        const header = document.createElement('div');
        header.className = 'chart-header';
        const title = document.createElement('h3');
        title.textContent = config.label;
        header.appendChild(title);
        card.appendChild(header);

        // Custom Legend Container
        const legendContainer = document.createElement('div');
        legendContainer.className = 'chart-legend';
        card.appendChild(legendContainer);

        const chartContainer = document.createElement('div');
        chartContainer.className = 'chart-container';
        const canvas = document.createElement('canvas');
        chartContainer.appendChild(canvas);
        card.appendChild(chartContainer);

        container.appendChild(card);

        const ctx = canvas.getContext('2d');

        let datasets = [];
        let datasetConfigs = [];

        if (config.type === 'composed') {
            // Total line
            datasetConfigs.push({ label: config.total, key: config.total, color: '#d73a49', hidden: false });
            // Parts lines
            config.parts.forEach((part, i) => {
                // Show if it ends with '_used'
                const isUsed = part.endsWith('_used');
                datasetConfigs.push({
                    label: part,
                    key: part,
                    color: getHslColor(i, config.parts.length),
                    hidden: !isUsed
                });
            });
        } else if (config.multi) {
            config.multi.forEach((sub, i) => {
                datasetConfigs.push({ label: sub, key: sub, color: config.colors[i], hidden: false });
            });
        } else {
            datasetConfigs.push({ label: config.key, key: config.key, color: config.color, hidden: false, fill: true });
        }

        // Build datasets
        datasetConfigs.forEach(dsConfig => {
            datasets.push({
                label: dsConfig.label,
                data: data.metrics[dsConfig.key],
                borderColor: dsConfig.color,
                backgroundColor: dsConfig.fill ? hexToRgba(dsConfig.color, 0.1) : 'transparent',
                borderWidth: 1.5,
                pointRadius: 0,
                tension: 0.1,
                hidden: dsConfig.hidden
            });
        });

        const chart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: data.labels,
                datasets: datasets
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: {
                    mode: 'index',
                    intersect: false,
                },
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        mode: 'index',
                        intersect: false
                    }
                },
                scales: {
                    x: {
                        display: true,
                        grid: { color: '#ebeef0', drawTicks: false },
                        ticks: {
                            maxTicksLimit: 6,
                            color: '#768d99'
                        }
                    },
                    y: {
                        grid: { color: '#ebeef0' },
                        ticks: { color: '#768d99' },
                        beginAtZero: true
                    }
                }
            }
        });

        // Generate Custom Legend
        datasetConfigs.forEach((dsConfig, index) => {
            const item = document.createElement('div');
            item.className = 'legend-item';

            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.checked = !dsConfig.hidden;
            checkbox.id = `legend-${config.label}-${index}`;

            const colorBox = document.createElement('span');
            colorBox.className = 'legend-color-box';
            colorBox.style.backgroundColor = dsConfig.color;

            const label = document.createElement('label');
            label.htmlFor = checkbox.id;
            label.textContent = dsConfig.label;
            label.style.cursor = 'pointer';

            item.appendChild(checkbox);
            item.appendChild(colorBox);
            item.appendChild(label);
            legendContainer.appendChild(item);

            // Event Listener
            checkbox.addEventListener('change', (e) => {
                const isChecked = e.target.checked;
                chart.setDatasetVisibility(index, isChecked);
                chart.update();
            });
        });
    });
}

function getHslColor(index, total) {
    const hue = (index * (360 / total)) % 360;
    return `hsl(${hue}, 70%, 45%)`;
}

function hexToRgba(hex, alpha) {
    const r = parseInt(hex.slice(1, 3), 16);
    const g = parseInt(hex.slice(3, 5), 16);
    const b = parseInt(hex.slice(5, 7), 16);
    return `rgba(${r}, ${g}, ${b}, ${alpha})`;
}
