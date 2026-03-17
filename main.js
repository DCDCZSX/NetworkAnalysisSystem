const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const fs = require('fs');

let mainWindow;
let analyzerProcess = null;
let currentCsvPath = null;

// C 后端可执行文件路径
const C_EXE = path.join(__dirname, 'backend', 'build', 'network_analyzer.exe');
const TEMP_CSV = path.join(__dirname, 'temp_data.csv');

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1400,
        height: 900,
        webPreferences: {
            nodeIntegration: true,
            contextIsolation: false
        },
        icon: path.join(__dirname, 'icon.png')
    });

    mainWindow.loadFile('index.html');

    // 开发模式下打开开发者工具
    // mainWindow.webContents.openDevTools();

    mainWindow.on('closed', () => {
        if (analyzerProcess) {
            analyzerProcess.kill();
        }
        mainWindow = null;
    });
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') {
        app.quit();
    }
});

app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
        createWindow();
    }
});

// 运行 C 程序并获取输出
function runAnalyzer(commands) {
    return new Promise((resolve, reject) => {
        const proc = spawn(C_EXE, [], {
            cwd: __dirname
        });

        let output = '';
        let errorOutput = '';

        proc.stdout.on('data', (data) => {
            output += data.toString();
        });

        proc.stderr.on('data', (data) => {
            errorOutput += data.toString();
        });

        proc.on('close', (code) => {
            if (code !== 0 && errorOutput) {
                reject(new Error(errorOutput));
            } else {
                resolve(output);
            }
        });

        proc.on('error', (err) => {
            reject(err);
        });

        // 发送命令到 C 程序
        commands.forEach(cmd => {
            proc.stdin.write(cmd + '\n');
        });
        proc.stdin.end();
    });
}

// 加载 CSV 文件
ipcMain.handle('load-csv', async (event, filePath) => {
    try {
        if (!filePath) {
            const result = await dialog.showOpenDialog(mainWindow, {
                properties: ['openFile'],
                filters: [
                    { name: 'CSV Files', extensions: ['csv'] },
                    { name: 'All Files', extensions: ['*'] }
                ]
            });

            if (result.canceled) {
                return { success: false, message: 'User cancelled' };
            }
            filePath = result.filePaths[0];
        }

        // 复制文件到临时位置（避免中文路径问题）
        fs.copyFileSync(filePath, TEMP_CSV);

        const output = await runAnalyzer(['8', 'temp_data.csv', '0']);

        if (output.includes('[Success]') || output.includes('Graph built successfully')) {
            currentCsvPath = 'temp_data.csv';
            return {
                success: true,
                message: `CSV file loaded successfully!\n\nFile: ${path.basename(filePath)}`,
                filePath: filePath
            };
        } else {
            return { success: false, message: 'Failed to load CSV file' };
        }
    } catch (error) {
        return { success: false, message: error.message };
    }
});

// 获取 Top N 节点
ipcMain.handle('get-top-nodes', async (event, topN = 10) => {
    try {
        if (!currentCsvPath) {
            return { success: false, message: 'No CSV file loaded' };
        }

        const output = await runAnalyzer(['8', currentCsvPath, '2', '0']);
        const nodes = parseTrafficNodes(output, topN);

        if (nodes.length === 0) {
            return { success: false, message: 'No data found' };
        }

        return { success: true, data: nodes };
    } catch (error) {
        return { success: false, message: error.message };
    }
});

// 获取 HTTPS 节点
ipcMain.handle('get-https-nodes', async () => {
    try {
        if (!currentCsvPath) {
            return { success: false, message: 'No CSV file loaded' };
        }

        const output = await runAnalyzer(['8', currentCsvPath, '10', '0']);
        const nodes = parseTrafficNodes(output, 100);

        if (nodes.length === 0) {
            return { success: false, message: 'No HTTPS data found' };
        }

        return { success: true, data: nodes };
    } catch (error) {
        return { success: false, message: error.message };
    }
});

// 检测异常节点
ipcMain.handle('detect-anomaly', async () => {
    try {
        if (!currentCsvPath) {
            return { success: false, message: 'No CSV file loaded' };
        }

        const output = await runAnalyzer(['8', currentCsvPath, '4', '0']);
        const nodes = parseTrafficNodes(output, 100);

        if (nodes.length === 0) {
            return { success: false, message: 'No anomalies detected' };
        }

        return { success: true, data: nodes };
    } catch (error) {
        return { success: false, message: error.message };
    }
});

// 查找最短路径
ipcMain.handle('find-path', async (event, srcIp, dstIp) => {
    try {
        if (!currentCsvPath) {
            return { success: false, message: 'No CSV file loaded' };
        }

        const output = await runAnalyzer(['8', currentCsvPath, '5', srcIp, dstIp, '0']);
        const path = parsePath(output);

        return { success: true, data: path };
    } catch (error) {
        return { success: false, message: error.message };
    }
});

// 获取单向流量节点（>80%）
ipcMain.handle('get-unidirectional-nodes', async () => {
    try {
        if (!currentCsvPath) {
            return { success: false, message: 'No CSV file loaded' };
        }

        const output = await runAnalyzer(['8', currentCsvPath, '11', '0']);
        const nodes = parseUnidirectionalNodes(output);

        if (nodes.length === 0) {
            return { success: false, message: 'No unidirectional nodes found' };
        }

        return { success: true, data: nodes };
    } catch (error) {
        return { success: false, message: error.message };
    }
});

// 查找星型结构
ipcMain.handle('find-star-structures', async () => {
    try {
        if (!currentCsvPath) {
            return { success: false, message: 'No CSV file loaded' };
        }

        const output = await runAnalyzer(['8', currentCsvPath, '6', '0']);
        const structures = parseStarStructures(output);

        if (structures.length === 0) {
            return { success: false, message: 'No star structures found' };
        }

        return { success: true, data: structures };
    } catch (error) {
        return { success: false, message: error.message };
    }
});

// ACL 检查
ipcMain.handle('check-acl', async (event, params) => {
    try {
        if (!currentCsvPath) {
            return { success: false, message: 'No CSV file loaded' };
        }

        const { targetIp, startIp, endIp, ruleType } = params;
        const output = await runAnalyzer(['8', currentCsvPath, '7', targetIp, startIp, endIp, ruleType, '0']);
        const aclData = parseACLResults(output, params);

        return { success: true, data: aclData };
    } catch (error) {
        return { success: false, message: error.message };
    }
});

// 解析流量节点数据
function parseTrafficNodes(output, limit) {
    const nodes = [];
    const lines = output.split('\n');

    for (const line of lines) {
        // 匹配格式: "1      183.94.22.88     12045148         188359           12233507"
        const match = line.match(/^\d+\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\d+)\s+(\d+)/);
        if (match) {
            const [, ip, inTraffic, outTraffic, total] = match;
            nodes.push({
                ip,
                total: parseInt(total),
                inTraffic: parseInt(inTraffic),
                outTraffic: parseInt(outTraffic),
                https: 0  // 默认值，HTTPS 查询会更新
            });
            if (nodes.length >= limit) break;
        }
    }

    return nodes;
}

// 解析单向流量节点数据（>80%）
function parseUnidirectionalNodes(output) {
    const nodes = [];
    const lines = output.split('\n');

    for (const line of lines) {
        // 匹配格式: "116.153.60.140   12187055         11999909            98.46%"
        const match = line.match(/^(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\d+)\s+([\d.]+)%/);
        if (match) {
            const [, ip, total, outTraffic, ratio] = match;
            nodes.push({
                ip,
                total: parseInt(total),
                inTraffic: parseInt(total) - parseInt(outTraffic),
                outTraffic: parseInt(outTraffic),
                ratio: parseFloat(ratio),
                https: 0
            });
        }
    }

    return nodes;
}

function parsePath(output) {
    const lines = output.split('\n');
    const result = {
        bfs: { nodes: [], hops: 0 },
        dijkstra: { nodes: [], hops: 0, congestion: 0 }
    };

    let currentAlgorithm = null;

    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        // 检测 BFS 部分
        if (line.includes('--- BFS Shortest Path ---')) {
            currentAlgorithm = 'bfs';
            continue;
        }

        // 检测 Dijkstra 部分
        if (line.includes('--- Dijkstra Minimum Congestion Path ---')) {
            currentAlgorithm = 'dijkstra';
            continue;
        }

        // 解析 BFS 路径
        if (currentAlgorithm === 'bfs' && line.includes('BFS Shortest Path:')) {
            const lengthMatch = line.match(/Path length = (\d+)/);
            if (lengthMatch) {
                result.bfs.hops = parseInt(lengthMatch[1]);
            }

            // 下一行是路径
            if (i + 1 < lines.length) {
                const pathLine = lines[i + 1];
                const pathParts = pathLine.split('->');
                result.bfs.nodes = pathParts.map(p => p.trim()).filter(p => p && p.includes('.'));
            }
        }

        // 解析 Dijkstra 路径
        if (currentAlgorithm === 'dijkstra' && line.includes('Dijkstra Minimum Congestion Path:')) {
            const lengthMatch = line.match(/Path length = (\d+)/);
            const congestionMatch = line.match(/Congestion weight = ([\d.]+)/);

            if (lengthMatch) {
                result.dijkstra.hops = parseInt(lengthMatch[1]);
            }
            if (congestionMatch) {
                result.dijkstra.congestion = parseFloat(congestionMatch[1]);
            }

            // 下一行是路径
            if (i + 1 < lines.length) {
                const pathLine = lines[i + 1];
                const pathParts = pathLine.split('->');
                result.dijkstra.nodes = pathParts.map(p => p.trim()).filter(p => p && p.includes('.'));
            }
        }
    }

    return result;
}

// 解析星型结构
function parseStarStructures(output) {
    const structures = [];
    const lines = output.split('\n');

    for (const line of lines) {
        // 匹配格式: "Center node 218.106.117.236 | Direct neighbors: 30 | Exclusive neighbors: 25"
        const match = line.match(/Center node (\S+) \| Direct neighbors: (\d+) \| Exclusive neighbors: (\d+)/);
        if (match) {
            const [, center, directNeighbors, exclusiveNeighbors] = match;

            // 查找下一行的 Exclusive list
            const lineIndex = lines.indexOf(line);
            let exclusiveList = '';
            if (lineIndex + 1 < lines.length) {
                const nextLine = lines[lineIndex + 1];
                if (nextLine.includes('Exclusive list:')) {
                    exclusiveList = nextLine.replace('Exclusive list:', '').trim();
                }
            }

            structures.push({
                center,
                directNeighbors: parseInt(directNeighbors),
                exclusiveNeighbors: parseInt(exclusiveNeighbors),
                exclusiveList
            });
        }
    }

    return structures;
}

// 解析 ACL 结果
function parseACLResults(output, params) {
    const violations = [];
    const lines = output.split('\n');

    for (const line of lines) {
        // 匹配格式: "  183.94.22.88 -> 116.153.60.140, Traffic: 187146 bytes"
        const match = line.match(/(\d+\.\d+\.\d+\.\d+)\s*->\s*(\d+\.\d+\.\d+\.\d+).*?(\d+)\s+bytes/);
        if (match) {
            const [, source, destination, traffic] = match;
            violations.push({
                source,
                destination,
                traffic: parseInt(traffic)
            });
        }
    }

    return {
        targetIp: params.targetIp,
        violations
    };
}
