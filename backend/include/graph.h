/**
 * 网络流量分析系统 - 图操作模块
 *
 * 提供图的创建、销毁、边的添加等基本操作
 */

#ifndef GRAPH_H
#define GRAPH_H

#include "types.h"

/**
 * 创建图
 * @return 返回初始化后的图指针
 */
Graph* create_graph();

/**
 * 释放图的所有内存
 * @param graph 要释放的图指针
 */
void free_graph(Graph* graph);

/**
 * 销毁图并释放所有内存（free_graph的别名）
 * @param graph 图指针
 */
void destroy_graph(Graph* graph);

/**
 * 添加或更新边（合并相同源-目标对的多次会话）
 * @param graph 图指针
 * @param src_ip 源IP地址
 * @param dst_ip 目标IP地址
 * @param protocol 协议号
 * @param dst_port 目标端口
 * @param data_size 流量大小
 * @param duration 时长
 */
void add_or_update_edge(Graph* graph, const char* src_ip, const char* dst_ip,
                        int protocol, int src_port, int dst_port, long long data_size, long long duration);

/**
 * 添加边到图中（简化版接口）
 * @param graph 图指针
 * @param src_ip 源IP地址
 * @param dst_ip 目标IP地址
 * @param protocol 协议名称字符串（如"HTTP", "HTTPS"）
 * @param bytes 流量字节数
 */
void add_edge(Graph* graph, const char* src_ip, const char* dst_ip,
              const char* protocol, int bytes);

/**
 * 查找节点
 * @param graph 图指针
 * @param ip IP地址
 * @return 节点指针，不存在返回NULL
 */
Node* find_node(Graph* graph, const char* ip);

/**
 * 从CSV文件读取网络流量数据并构建图
 * @param graph 图指针
 * @param filename CSV文件路径
 * @return 成功返回0，失败返回-1
 */
int load_data_from_csv(Graph* graph, const char* filename);
int load_data_from_pcapng(Graph* graph, const char* filename);

/**
 * 导出网络图到CSV文件
 * @param graph 图指针
 * @param filename 输出文件路径
 */
void export_network_graph_csv(Graph* graph, const char* filename);

#endif // GRAPH_H
