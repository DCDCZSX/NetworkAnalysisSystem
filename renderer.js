const { ipcRenderer } = require('electron');

let currentView = 'data';

// 导航切换
document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', () => {
        const view = item.dataset.view;
        switchView(view);
    });
});

function switchView(view) {
    // 更新导航状态
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
        if (item.dataset.view === view) {
            item.classList.add('active');
        }
    });

    // 更新视图
    document.querySelectorAll('.view').forEach(v => {
        v.classList.remove('active');
    });
    document.getElementById(`${view}-view`).classList.add('active');

    // 更新标题
    const titles = {
        'data': 'Data Management',
        'traffic': 'Traffic Analysis',
        'security': 'Security Analysis',
        'topology': 'Network Topology',
        'path': 'Path Analysis'
    };
    document.getElementById('page-title').textContent = titles[view];

    currentView = view;
}

// 加载 CSV 文件
document.getElementById('load-csv-btn').addEventListener('click', async () => {
    try {
        const result = await ipcRenderer.invoke('load-csv');
        if (result.success) {
            document.getElementById('current-file').textContent = result.filePath;
            showMessage(result.message, 'success');
        } else {
            showMessage(result.message, 'error');
        }
    } catch (error) {
        showMessage('Error: ' + error.message, 'error');
    }
});

// Top 10 节点
document.getElementById('top-nodes-btn').addEventListener('click', async () => {
    const container = document.getElementById('traffic-results');
    container.innerHTML = '<div class="loading">Loading...</div>';

    try {
        const result = await ipcRenderer.invoke('get-top-nodes', 10);
        if (result.success) {
            displayTrafficNodes(result.data, container);
        } else {
            container.innerHTML = `<div class="error">${result.message}</div>`;
        }
    } catch (error) {
        container.innerHTML = `<div class="error">Error: ${error.message}</div>`;
    }
});

// HTTPS 节点
document.getElementById('https-nodes-btn').addEventListener('click', async () => {
    const container = document.getElementById('traffic-results');
    container.innerHTML = '<div class="loading">Loading...</div>';

    try {
        const result = await ipcRenderer.invoke('get-https-nodes');
        if (result.success) {
            displayTrafficNodes(result.data, container);
        } else {
            container.innerHTML = `<div class="error">${result.message}</div>`;
        }
    } catch (error) {
        container.innerHTML = `<div class="error">Error: ${error.message}</div>`;
    }
});

// 异常检测
document.getElementById('anomaly-btn').addEventListener('click', async () => {
    const container = document.getElementById('security-results');
    container.innerHTML = '<div class="loading">Loading...</div>';

    try {
        const result = await ipcRenderer.invoke('detect-anomaly');
        if (result.success) {
            displayTrafficNodes(result.data, container);
        } else {
            container.innerHTML = `<div class="error">${result.message}</div>`;
        }
    } catch (error) {
        container.innerHTML = `<div class="error">Error: ${error.message}</div>`;
    }
});

// 路径查找
document.getElementById('find-path-btn').addEventListener('click', async () => {
    const srcIp = document.getElementById('src-ip').value.trim();
    const dstIp = document.getElementById('dst-ip').value.trim();
    const container = document.getElementById('path-results');

    if (!srcIp || !dstIp) {
        container.innerHTML = '<div class="error">Please enter both source and destination IP addresses</div>';
        return;
    }

    container.innerHTML = '<div class="loading">Finding path...</div>';

    try {
        const result = await ipcRenderer.invoke('find-path', srcIp, dstIp);
        if (result.success) {
            displayPath(result.data, container);
        } else {
            container.innerHTML = `<div class="error">${result.message}</div>`;
        }
    } catch (error) {
        container.innerHTML = `<div class="error">Error: ${error.message}</div>`;
    }
});

// 显示流量节点
function displayTrafficNodes(nodes, container) {
    if (!nodes || nodes.length === 0) {
        container.innerHTML = '<div class="error">No data found</div>';
        return;
    }

    let html = '<h3>Results</h3>';
    nodes.forEach((node, index) => {
        html += `
            <div class="node-item">
                <div class="ip">#${index + 1} ${node.ip}</div>
                <div class="stats">
                    <div>Total: ${formatBytes(node.total)}</div>
                    <div>In: ${formatBytes(node.inTraffic)}</div>
                    <div>Out: ${formatBytes(node.outTraffic)}</div>
                    <div>HTTPS: ${formatBytes(node.https)}</div>
                </div>
            </div>
        `;
    });

    container.innerHTML = html;
}

// 显示路径
function displayPath(pathData, container) {
    if (!pathData || (!pathData.bfs && !pathData.dijkstra)) {
        container.innerHTML = '<div class="error">No path found</div>';
        return;
    }

    let html = '<h3>Path Comparison: BFS vs Dijkstra</h3>';

    // BFS 结果
    if (pathData.bfs && pathData.bfs.nodes && pathData.bfs.nodes.length > 0) {
        html += `
            <div class="path-section">
                <h4>🔵 BFS (Breadth-First Search) - Shortest Hops</h4>
                <div class="path-item">
                    <div class="path-stats">
                        <span><strong>Hops:</strong> ${pathData.bfs.hops}</span>
                    </div>
                    <div class="path-nodes">
        `;

        pathData.bfs.nodes.forEach((node, index) => {
            html += `<div class="path-node">${node}</div>`;
            if (index < pathData.bfs.nodes.length - 1) {
                html += '<div class="arrow">→</div>';
            }
        });

        html += `
                    </div>
                </div>
            </div>
        `;
    }

    // Dijkstra 结果
    if (pathData.dijkstra && pathData.dijkstra.nodes && pathData.dijkstra.nodes.length > 0) {
        html += `
            <div class="path-section">
                <h4>🟢 Dijkstra - Minimum Congestion</h4>
                <div class="path-item">
                    <div class="path-stats">
                        <span><strong>Hops:</strong> ${pathData.dijkstra.hops}</span>
                        <span><strong>Congestion:</strong> ${pathData.dijkstra.congestion.toFixed(4)}</span>
                    </div>
                    <div class="path-nodes">
        `;

        pathData.dijkstra.nodes.forEach((node, index) => {
            html += `<div class="path-node">${node}</div>`;
            if (index < pathData.dijkstra.nodes.length - 1) {
                html += '<div class="arrow">→</div>';
            }
        });

        html += `
                    </div>
                </div>
            </div>
        `;
    }

    // 对比总结
    if (pathData.bfs.nodes.length > 0 && pathData.dijkstra.nodes.length > 0) {
        html += `
            <div class="comparison-summary">
                <h4>📊 Comparison Summary</h4>
                <div class="comparison-grid">
                    <div class="comparison-item">
                        <strong>Hop Count Difference:</strong>
                        ${Math.abs(pathData.bfs.hops - pathData.dijkstra.hops)}
                        ${pathData.bfs.hops < pathData.dijkstra.hops ? '(BFS shorter)' :
                          pathData.bfs.hops > pathData.dijkstra.hops ? '(Dijkstra shorter)' : '(Same)'}
                    </div>
                    <div class="comparison-item">
                        <strong>Dijkstra Congestion Weight:</strong> ${pathData.dijkstra.congestion.toFixed(4)}
                    </div>
                    <div class="comparison-item">
                        <strong>Recommendation:</strong>
                        ${pathData.bfs.hops === pathData.dijkstra.hops ?
                          'Both paths have same hop count, Dijkstra path has lower congestion' :
                          pathData.bfs.hops < pathData.dijkstra.hops ?
                          'BFS path is shorter but may have higher congestion' :
                          'Dijkstra path is both shorter and less congested'}
                    </div>
                </div>
            </div>
        `;
    }

    container.innerHTML = html;
}

// 格式化字节数
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

// 显示消息
function showMessage(message, type) {
    const container = document.querySelector('.content-area');
    const msgDiv = document.createElement('div');
    msgDiv.className = type;
    msgDiv.textContent = message;
    msgDiv.style.position = 'fixed';
    msgDiv.style.top = '20px';
    msgDiv.style.right = '20px';
    msgDiv.style.zIndex = '1000';
    msgDiv.style.maxWidth = '400px';

    container.appendChild(msgDiv);

    setTimeout(() => {
        msgDiv.remove();
    }, 3000);
}

// 单向流量筛选
document.getElementById('unidirectional-btn').addEventListener('click', async () => {
    const container = document.getElementById('traffic-results');
    container.innerHTML = '<div class="loading">Loading...</div>';

    try {
        const result = await ipcRenderer.invoke('get-unidirectional-nodes');
        if (result.success) {
            displayTrafficNodes(result.data, container);
        } else {
            container.innerHTML = `<div class="error">${result.message}</div>`;
        }
    } catch (error) {
        container.innerHTML = `<div class="error">Error: ${error.message}</div>`;
    }
});

// 星型结构检测
document.getElementById('star-structure-btn').addEventListener('click', async () => {
    const container = document.getElementById('topology-results');
    container.innerHTML = '<div class="loading">Analyzing...</div>';

    try {
        const result = await ipcRenderer.invoke('find-star-structures');
        if (result.success) {
            displayStarStructures(result.data, container);
        } else {
            container.innerHTML = `<div class="error">${result.message}</div>`;
        }
    } catch (error) {
        container.innerHTML = `<div class="error">Error: ${error.message}</div>`;
    }
});

// ACL 检查
document.getElementById('acl-check-btn').addEventListener('click', async () => {
    const targetIp = document.getElementById('acl-target-ip').value.trim();
    const startIp = document.getElementById('acl-start-ip').value.trim();
    const endIp = document.getElementById('acl-end-ip').value.trim();
    const ruleType = document.getElementById('acl-rule-type').value;
    const container = document.getElementById('security-results');

    if (!targetIp || !startIp || !endIp) {
        container.innerHTML = '<div class="error">Please enter all IP addresses (Target, Start, End)</div>';
        return;
    }

    container.innerHTML = '<div class="loading">Checking ACL...</div>';

    try {
        const result = await ipcRenderer.invoke('check-acl', { targetIp, startIp, endIp, ruleType });
        if (result.success) {
            displayACLResults(result.data, container, { targetIp, startIp, endIp, ruleType });
        } else {
            container.innerHTML = `<div class="error">${result.message}</div>`;
        }
    } catch (error) {
        container.innerHTML = `<div class="error">Error: ${error.message}</div>`;
    }
});

// 显示星型结构
function displayStarStructures(structures, container) {
    if (!structures || structures.length === 0) {
        container.innerHTML = '<div class="error">No star structures found</div>';
        return;
    }

    let html = '<h3>Star Structures Found</h3>';
    structures.forEach((star, index) => {
        html += `
            <div class="node-item">
                <div class="ip">Star #${index + 1}: ${star.center}</div>
                <div class="stats">
                    <div>Direct Neighbors: ${star.directNeighbors}</div>
                    <div>Exclusive Neighbors: ${star.exclusiveNeighbors}</div>
                </div>
                <div class="exclusive-list">
                    <strong>Exclusive nodes:</strong> ${star.exclusiveList}
                </div>
            </div>
        `;
    });

    container.innerHTML = html;
}

// 显示 ACL 结果
function displayACLResults(aclData, container, params) {
    if (!aclData || !aclData.violations || aclData.violations.length === 0) {
        container.innerHTML = `
            <div class="success-message" style="background: #064e3b; border: 1px solid #059669; padding: 20px; border-radius: 8px; color: #10b981;">
                <h3>✓ No ACL Violations Found</h3>
                <p>Target IP <strong>${params.targetIp}</strong> has no violations for the rule:</p>
                <p><strong>${params.ruleType}</strong> connections with IP range: ${params.startIp} - ${params.endIp}</p>
            </div>
        `;
        return;
    }

    let html = `
        <div class="acl-header" style="background: #7f1d1d; border: 1px solid #dc2626; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
            <h3>⚠️ ACL Violations Detected</h3>
            <div style="color: #fca5a5; margin-top: 10px;">
                <div><strong>Target IP:</strong> ${params.targetIp}</div>
                <div><strong>Rule Type:</strong> ${params.ruleType}</div>
                <div><strong>IP Range:</strong> ${params.startIp} - ${params.endIp}</div>
                <div><strong>Total Violations:</strong> ${aclData.violations.length}</div>
            </div>
        </div>
        <h4>Violating Connections:</h4>
    `;

    aclData.violations.forEach((conn, index) => {
        html += `
            <div class="node-item" style="border-left: 3px solid #dc2626;">
                <div class="ip">#${index + 1} ${conn.source} → ${conn.destination}</div>
                <div class="stats">
                    <div>Traffic: ${formatBytes(conn.traffic)}</div>
                </div>
            </div>
        `;
    });

    container.innerHTML = html;
}

// 实时抓包功能
let captureProcess = null;

document.getElementById('start-capture-btn').addEventListener('click', async () => {
    const duration = parseInt(document.getElementById('capture-duration').value);
    const startBtn = document.getElementById('start-capture-btn');
    const stopBtn = document.getElementById('stop-capture-btn');
    const loadBtn = document.getElementById('load-captured-btn');
    const statusDiv = document.getElementById('capture-status');
    const infoDiv = document.getElementById('capture-info');
    const resultsDiv = document.getElementById('capture-results');

    startBtn.disabled = true;
    stopBtn.disabled = false;
    loadBtn.disabled = true;
    statusDiv.style.display = 'block';
    infoDiv.innerHTML = '🔄 Starting packet capture...';
    resultsDiv.innerHTML = '';

    try {
        const result = await ipcRenderer.invoke('start-capture', duration);
        if (result.success) {
            infoDiv.innerHTML = `
                ✅ Capture started<br>
                Duration: ${duration} seconds<br>
                Status: Capturing packets...
            `;
        } else {
            infoDiv.innerHTML = `❌ Failed to start capture: ${result.message}`;
            startBtn.disabled = false;
            stopBtn.disabled = true;
        }
    } catch (error) {
        infoDiv.innerHTML = `❌ Error: ${error.message}`;
        startBtn.disabled = false;
        stopBtn.disabled = true;
    }
});

document.getElementById('stop-capture-btn').addEventListener('click', async () => {
    const startBtn = document.getElementById('start-capture-btn');
    const stopBtn = document.getElementById('stop-capture-btn');
    const infoDiv = document.getElementById('capture-info');

    stopBtn.disabled = true;
    infoDiv.innerHTML = '⏹️ Stopping capture...';

    try {
        const result = await ipcRenderer.invoke('stop-capture');
        if (result.success) {
            infoDiv.innerHTML = `✅ Capture stopped<br>Captured ${result.flows} flows`;
            startBtn.disabled = false;
            document.getElementById('load-captured-btn').disabled = false;
        } else {
            infoDiv.innerHTML = `❌ ${result.message}`;
            startBtn.disabled = false;
        }
    } catch (error) {
        infoDiv.innerHTML = `❌ Error: ${error.message}`;
        startBtn.disabled = false;
    }
});

document.getElementById('load-captured-btn').addEventListener('click', async () => {
    const resultsDiv = document.getElementById('capture-results');
    const infoDiv = document.getElementById('capture-info');

    resultsDiv.innerHTML = '<div class="loading">Loading captured data...</div>';

    try {
        const result = await ipcRenderer.invoke('load-captured-data');
        if (result.success) {
            infoDiv.innerHTML = `✅ Data loaded successfully<br>Total nodes: ${result.nodeCount}`;
            resultsDiv.innerHTML = `
                <div class="success-message" style="background: #064e3b; border: 1px solid #059669; padding: 20px; border-radius: 8px; color: #10b981;">
                    <h3>✓ Captured Data Loaded</h3>
                    <p>Successfully loaded ${result.nodeCount} nodes from captured traffic</p>
                    <p>You can now use other analysis functions with this data</p>
                </div>
            `;
        } else {
            resultsDiv.innerHTML = `<div class="error">${result.message}</div>`;
        }
    } catch (error) {
        resultsDiv.innerHTML = `<div class="error">Error: ${error.message}</div>`;
    }
});

// 监听抓包进度更新
ipcRenderer.on('capture-progress', (event, data) => {
    const infoDiv = document.getElementById('capture-info');
    infoDiv.innerHTML = `
        📡 Capturing packets...<br>
        ${data.message}
    `;
});

// 监听抓包完成
ipcRenderer.on('capture-complete', (event, data) => {
    const startBtn = document.getElementById('start-capture-btn');
    const stopBtn = document.getElementById('stop-capture-btn');
    const loadBtn = document.getElementById('load-captured-btn');
    const infoDiv = document.getElementById('capture-info');

    startBtn.disabled = false;
    stopBtn.disabled = true;
    loadBtn.disabled = false;

    infoDiv.innerHTML = `
        ✅ Capture completed<br>
        Captured ${data.flows} flows<br>
        Output file: captured.csv
    `;
});
