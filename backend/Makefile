# 网络流量分析与异常检测系统 - Makefile
# 模块化项目构建脚本

# 编译器和编译选项
CC = gcc
CFLAGS = -Wall -Wextra -g -std=c99 -Iinclude
LDFLAGS =

# 目录定义
SRC_DIR = src
INC_DIR = include
BUILD_DIR = build
DATA_DIR = data
DOCS_DIR = docs
SCRIPTS_DIR = scripts

# 目标文件
TARGET = $(BUILD_DIR)/network_analyzer
ifeq ($(OS),Windows_NT)
    TARGET := $(TARGET).exe
endif

# 源文件
SOURCES = $(SRC_DIR)/main.c \
          $(SRC_DIR)/graph.c \
          $(SRC_DIR)/hash.c \
          $(SRC_DIR)/analysis.c \
          $(SRC_DIR)/algorithm.c

# 目标文件
OBJECTS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SOURCES))

# 头文件
HEADERS = $(INC_DIR)/types.h \
          $(INC_DIR)/graph.h \
          $(INC_DIR)/hash.h \
          $(INC_DIR)/analysis.h \
          $(INC_DIR)/algorithm.h

# 默认目标：编译程序
all: $(TARGET)
	@echo "=========================================="
	@echo "编译完成！"
	@echo "可执行文件: $(TARGET)"
	@echo "运行命令: $(TARGET)"
	@echo "=========================================="

# 创建构建目录
$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

# 链接目标文件生成可执行文件
$(TARGET): $(BUILD_DIR) $(OBJECTS)
	@echo "正在链接..."
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJECTS) $(LDFLAGS)

# 编译源文件
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c $(HEADERS)
	@echo "正在编译 $<..."
	$(CC) $(CFLAGS) -c $< -o $@

# 运行程序
run: $(TARGET)
	@echo ""
	@echo "=========================================="
	@echo "启动网络流量分析系统..."
	@echo "=========================================="
	@cd $(BUILD_DIR) && ./$(notdir $(TARGET))

# 清理编译产物
clean:
	@echo "正在清理编译产物..."
	rm -rf $(BUILD_DIR)/*.o $(TARGET)
	@echo "清理完成"

# 清理所有生成文件
cleanall: clean
	@echo "正在清理所有生成文件..."
	rm -rf $(BUILD_DIR)
	@echo "已清理所有生成文件"

# 显示项目结构
tree:
	@echo "项目结构："
	@echo "course_design/"
	@echo "├── include/          # 头文件"
	@echo "│   ├── types.h"
	@echo "│   ├── graph.h"
	@echo "│   ├── hash.h"
	@echo "│   ├── analysis.h"
	@echo "│   └── algorithm.h"
	@echo "├── src/              # 源代码"
	@echo "│   ├── main.c"
	@echo "│   ├── graph.c"
	@echo "│   ├── hash.c"
	@echo "│   ├── analysis.c"
	@echo "│   └── algorithm.c"
	@echo "├── data/             # 数据文件"
	@echo "│   └── network_data.csv"
	@echo "├── build/            # 编译输出"
	@echo "├── docs/             # 文档"
	@echo "└── scripts/          # 脚本工具"

# 显示帮助信息
help:
	@echo "网络流量分析系统 - Makefile 使用说明"
	@echo ""
	@echo "可用命令："
	@echo "  make          - 编译程序"
	@echo "  make run      - 编译并运行程序"
	@echo "  make clean    - 清理编译产物"
	@echo "  make cleanall - 清理所有生成文件"
	@echo "  make tree     - 显示项目结构"
	@echo "  make help     - 显示此帮助信息"
	@echo ""
	@echo "项目结构："
	@echo "  include/      - 头文件目录"
	@echo "  src/          - 源代码目录"
	@echo "  data/         - 数据文件目录"
	@echo "  build/        - 编译输出目录"
	@echo "  docs/         - 文档目录"
	@echo "  scripts/      - 脚本工具目录"

# 安装（复制可执行文件到系统路径，可选）
install: $(TARGET)
	@echo "安装功能暂未实现"

# 声明伪目标
.PHONY: all run clean cleanall tree help install
