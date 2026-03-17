# Network Traffic Analysis & Anomaly Detection System

一个基于 Electron + C 语言的网络流量分析与异常检测系统。

## 功能特性

### 📊 流量分析
- **Top 10 Nodes** - 显示流量最高的 10 个节点
- **HTTPS Traffic** - 分析 HTTPS 流量分布
- **Unidirectional >80%** - 筛选单向流量占比超过 80% 的节点

### 🔒 安全检测
- **Anomaly Detection** - 检测疑似端口扫描等异常行为
- **ACL Check** - 访问控制列表检查，检测违反规则的会话

### 🌐 拓扑分析
- **Star Structure Detection** - 检测网络中的星型拓扑结构

### 🛣️ 路径分析
- **BFS vs Dijkstra** - 对比两种算法的路径查找结果
- 显示跳数、拥塞程度和完整路径

## 技术栈

- **前端**: HTML + CSS + JavaScript
- **桌面框架**: Electron
- **后端**: C 语言（图算法、网络分析）
- **进程通信**: Node.js child_process

## 安装与运行

### 前置要求

- Node.js (v14+)
- GCC 编译器（用于编译 C 后端）

### 安装步骤

1. 克隆仓库
```bash
git clone https://github.com/DCDCZSX/NetworkAnalysisSystem.git
cd NetworkAnalysisSystem
```

2. 安装依赖
```bash
npm install
```

3. 编译 C 后端
```bash
cd backend
mkdir -p build
gcc -Wall -Wextra -g -std=c99 -Iinclude -c src/hash.c -o build/hash.o
gcc -Wall -Wextra -g -std=c99 -Iinclude -c src/graph.c -o build/graph.o
gcc -Wall -Wextra -g -std=c99 -Iinclude -c src/analysis.c -o build/analysis.o
gcc -Wall -Wextra -g -std=c99 -Iinclude -c src/algorithm.c -o build/algorithm.o
gcc -Wall -Wextra -g -std=c99 -Iinclude -c src/main.c -o build/main.o
gcc -o build/network_analyzer.exe build/*.o
cd ..
```

4. 启动应用
```bash
npm start
```

或者双击 `启动应用.bat`（Windows）

## 使用说明

1. **加载数据**
   - 点击右上角 "Load CSV File" 按钮
   - 选择网络流量 CSV 文件

2. **使用功能**
   - 左侧导航栏选择不同的分析模块
   - 每个模块提供不同的分析功能

3. **CSV 文件格式**
   ```
   timestamp,source_ip,destination_ip,source_port,destination_port,protocol,data_size
   ```

## 项目结构

```
electron_ui/
├── backend/              # C 语言后端
│   ├── src/              # 源代码
│   ├── include/          # 头文件
│   └── build/            # 编译输出
├── main.js               # Electron 主进程
├── renderer.js           # 渲染进程逻辑
├── index.html            # 界面
├── styles.css            # 样式
├── package.json          # 项目配置
└── 启动应用.bat          # Windows 启动脚本
```

## 截图

（可以添加应用截图）

## 开发

### 调试模式
```bash
npm start
```

### 打包应用
```bash
npm run build
```

## 许可证

本项目仅用于课程设计学习目的。

## 作者

DCDCZSX

## 更新日志

### v1.0.0 (2026-03-16)
- 初始版本发布
- 实现所有核心功能
- 完整的 UI 界面
