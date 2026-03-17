/**
 * 网络流量分析系统 - 路径查找算法模块
 *
 * 提供BFS和Dijkstra路径查找算法
 */

#ifndef ALGORITHM_H
#define ALGORITHM_H

#include "types.h"

/* ==================== 路径查找算法 ==================== */

/**
 * BFS路径查找 - 找到跳数最少的路径
 * @param graph 图指针
 * @param src_ip 源IP地址
 * @param dst_ip 目标IP地址
 * @return 路径结构体指针，如果不存在路径返回NULL
 */
Path* bfs_shortest_path(Graph* graph, const char* src_ip, const char* dst_ip);

/**
 * Dijkstra路径查找 - 找到拥塞程度最小的路径
 * @param graph 图指针
 * @param src_ip 源IP地址
 * @param dst_ip 目标IP地址
 * @return 路径结构体指针，如果不存在路径返回NULL
 */
Path* dijkstra_least_congestion_path(Graph* graph, const char* src_ip, const char* dst_ip);

/**
 * BFS路径查找（打印版本）
 * @param graph 图指针
 * @param src_ip 源IP
 * @param dst_ip 目标IP
 */
void find_path_bfs(Graph* graph, const char* src_ip, const char* dst_ip);

/**
 * Dijkstra路径查找（打印版本）
 * @param graph 图指针
 * @param src_ip 源IP
 * @param dst_ip 目标IP
 */
void find_path_dijkstra(Graph* graph, const char* src_ip, const char* dst_ip);

/**
 * 打印路径
 * @param graph 图指针
 * @param path 路径结构体指针
 * @param path_type 路径类型描述
 * @param show_weight 是否显示拥塞权重（1=显示，0=不显示）
 */
void print_path(Graph* graph, Path* path, const char* path_type, int show_weight);

/**
 * 释放路径内存
 * @param path 路径结构体指针
 */
void free_path(Path* path);

/* ==================== 优先队列操作 ==================== */

/**
 * 创建优先队列
 * @param capacity 容量
 * @return 优先队列指针
 */
PriorityQueue* create_priority_queue(int capacity);

/**
 * 释放优先队列
 * @param pq 优先队列指针
 */
void free_priority_queue(PriorityQueue* pq);

/**
 * 向优先队列中插入元素
 * @param pq 优先队列指针
 * @param vertex 顶点索引
 * @param distance 距离
 */
void pq_push(PriorityQueue* pq, int vertex, double distance);

/**
 * 从优先队列中弹出最小元素
 * @param pq 优先队列指针
 * @return 最小元素
 */
PQNode pq_pop(PriorityQueue* pq);

/**
 * 判断优先队列是否为空
 * @param pq 优先队列指针
 * @return 空返回1，否则返回0
 */
int pq_is_empty(PriorityQueue* pq);

#endif // ALGORITHM_H
