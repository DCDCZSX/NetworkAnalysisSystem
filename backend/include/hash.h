/**
 * 网络流量分析系统 - 哈希表模块
 *
 * 提供IP地址到节点索引的快速映射
 */

#ifndef HASH_H
#define HASH_H

#include "types.h"

/**
 * 哈希函数 - 将IP字符串映射为哈希值
 * @param ip IP地址字符串
 * @return 哈希值（0到HASH_TABLE_SIZE-1）
 */
unsigned int hash_function(const char* ip);

/**
 * 在哈希表中查找IP对应的节点索引
 * @param graph 图指针
 * @param ip IP地址字符串
 * @return 节点索引，如果不存在返回-1
 */
int find_ip_index(Graph* graph, const char* ip);

/**
 * 添加IP到图中（如果不存在）
 * @param graph 图指针
 * @param ip IP地址字符串
 * @return 该IP对应的节点索引
 */
int add_ip_to_graph(Graph* graph, const char* ip);

#endif // HASH_H
