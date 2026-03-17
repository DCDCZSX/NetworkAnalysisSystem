/**
 * 网络流量分析系统 - 基础类型定义
 *
 * 本文件定义了系统中使用的基础数据结构和常量
 */

#ifndef TYPES_H
#define TYPES_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

/* ==================== 常量定义 ==================== */
#define MAX_IP_LENGTH 16        // IP地址最大长度
#define HASH_TABLE_SIZE 1024    // 哈希表大小
#define MAX_NODES 5000          // 图中最大节点数
#define PROTOCOL_TCP 6          // TCP协议号
#define PROTOCOL_UDP 17         // UDP协议号
#define HTTPS_PORT 443          // HTTPS默认端口

/* ==================== 边结构定义 ==================== */
/**
 * 边结构体 - 表示从源节点到目标节点的连接
 */
typedef struct Edge {
    int dest_index;              // 目标节点索引
    long long total_data_size;   // 总流量大小（字节）
    long long total_duration;    // 总时长（毫秒）
    long long https_data_size;   // HTTPS流量大小
    struct Edge* next;           // 下一条边（链表）
} Edge;

/* ==================== 节点结构定义 ==================== */
/**
 * 节点结构体 - 表示网络中的一个IP地址
 */
typedef struct Node {
    char ip[MAX_IP_LENGTH];      // IP地址
    long long in_traffic;        // 入流量
    long long out_traffic;       // 出流量
    long long https_traffic;     // HTTPS流量
    Edge* edges;                 // 邻接表头指针
} Node;

/* ==================== 哈希表节点定义 ==================== */
/**
 * 哈希表节点 - 用于IP地址到索引的映射
 */
typedef struct HashNode {
    char ip[MAX_IP_LENGTH];      // IP地址
    int index;                   // 节点索引
    struct HashNode* next;       // 下一个哈希节点
} HashNode;

/* ==================== 图结构定义 ==================== */
/**
 * 图结构体 - 整个网络拓扑的表示
 */
typedef struct Graph {
    Node nodes[MAX_NODES];                    // 节点数组
    int node_count;                           // 当前节点数量
    HashNode* hash_table[HASH_TABLE_SIZE];   // 哈希表
} Graph;

/* ==================== 路径结构定义 ==================== */
/**
 * 路径结构体 - 用于存储路径查找结果
 */
typedef struct Path {
    int* nodes;          // 路径节点索引数组
    int length;          // 路径长度
    double weight;       // 路径权重
} Path;

/* ==================== 优先队列节点定义 ==================== */
/**
 * 优先队列节点 - 用于Dijkstra算法
 */
typedef struct PQNode {
    int vertex;          // 顶点索引
    double distance;     // 当前距离
} PQNode;

/**
 * 优先队列结构体
 */
typedef struct PriorityQueue {
    PQNode* nodes;       // 堆数组
    int size;            // 当前大小
    int capacity;        // 容量
} PriorityQueue;

#endif // TYPES_H
