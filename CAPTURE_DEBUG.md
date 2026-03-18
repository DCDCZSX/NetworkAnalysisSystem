# 实时抓包功能测试指南

## 问题诊断

如果点击 "Load Captured Data" 后显示 "No data found"，请按以下步骤排查：

### 1. 检查 captured.csv 文件

```bash
# 查看文件是否存在
ls -l captured.csv

# 查看文件内容
head -10 captured.csv
```

文件应该包含：
- 标题行：`Source,Destination,Protocol,SrcPort,DstPort,DataSize,Duration`
- 至少一行数据

### 2. 检查文件格式

确保每行有 7 个字段，用逗号分隔：
```
192.168.1.100,8.8.8.8,6,54321,443,1500,120.500
```

### 3. 手动测试 C 后端加载

```bash
cd electron_ui
printf "8\ncaptured.csv\n2\n0\n" | ./backend/build/network_analyzer.exe
```

应该看到：`[Info] Current graph has X nodes`

### 4. 查看控制台日志

打开 Electron 开发者工具（Ctrl+Shift+I），查看 Console 标签页的日志输出。

## 常见问题

### 问题 1：抓包没有数据

**原因**：
- 网络接口没有流量
- 权限不足（需要管理员权限）
- Scapy 未正确安装

**解决**：
```bash
# 安装 Scapy
pip install scapy

# Windows: 以管理员身份运行应用
# Linux/Mac: 使用 sudo
```

### 问题 2：Duration 格式错误

**原因**：Duration 字段应该是毫秒数（浮点数）

**解决**：已在 capture_packets.py 中修复，Duration 现在以毫秒为单位

### 问题 3：CSV 文件为空

**原因**：
- 抓包时间太短
- 没有网络流量

**解决**：
- 增加抓包时长（至少 30 秒）
- 在抓包期间访问网页或发送网络请求

## 测试步骤

### 快速测试（使用测试文件）

1. 运行测试脚本创建测试数据：
   ```bash
   python test_capture.py
   ```

2. 在应用中点击 "Load Captured Data"

3. 应该看到成功加载 4 个节点

### 完整测试（实际抓包）

1. 以管理员权限启动应用

2. 进入 "Live Capture" 页面

3. 设置抓包时长（建议 30-60 秒）

4. 点击 "Start Capture"

5. 在抓包期间：
   - 打开浏览器访问几个网站
   - 发送一些网络请求

6. 等待抓包完成

7. 点击 "Load Captured Data"

8. 检查是否成功加载

## 调试技巧

### 启用详细日志

在 main.js 中已添加详细日志，查看控制台输出：
- CSV 文件行数
- C 后端输出
- 解析的节点数量

### 手动验证 CSV

```bash
# 查看 CSV 内容
cat captured.csv

# 统计行数（减去标题行）
wc -l captured.csv
```

### 测试 C 后端

```bash
# 直接测试 C 程序加载 CSV
cd backend
./build/network_analyzer.exe
# 选择选项 8，输入 captured.csv 路径
```

## 修复记录

### 2026-03-16
- ✅ 修复 Duration 字段格式（改为毫秒）
- ✅ 添加详细的错误日志
- ✅ 添加文件内容验证
- ✅ 改进错误消息显示
