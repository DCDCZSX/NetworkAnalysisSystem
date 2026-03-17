/**
 * 网络流量分析系统 - 流量分析模块
 *
 * 提供流量统计、排序、异常检测等分析功能
 */

#ifndef ANALYSIS_H
#define ANALYSIS_H

#include "types.h"

/**
 * 节点流量排序 - 按总流量降序排序并输出前N个节点
 * @param graph 图指针
 * @param top_n 输出前N个节点
 */
void sort_nodes_by_traffic(Graph* graph, int top_n);

/**
 * HTTPS节点筛选 - 筛选包含HTTPS连接的节点
 * @param graph 图指针
 * @param top_n 输出前N个节点
 */
void https_nodes_sorted_by_total(Graph* graph);
void https_nodes_sorted_by_https(Graph* graph);

/**
 * 异常节点筛选 - 筛选单向发出流量占比 > 80%的节点
 * @param graph 图指针
 * @param top_n 输出前N个节点
 */
void filter_suspicious_nodes(Graph* graph, int top_n);

/**
 * 流量排行分析（便捷接口）
 * @param graph 图指针
 * @param top_n 显示前N名
 */
void analyze_traffic_ranking(Graph* graph, int top_n);

/**
 * 协议流量分析（便捷接口）
 * @param graph 图指针
 * @param protocol 协议名称（如"HTTPS"）
 */
void analyze_protocol_traffic(Graph* graph, const char* protocol);

/**
 * 异常节点检测（便捷接口）
 * @param graph 图指针
 * @param threshold 阈值（如0.8表示80%）
 */
void detect_anomaly_nodes(Graph* graph, double threshold);

/**
 * 查找所有星型结构（中心节点与>=20个且这些节点只与中心节点相连）
 * @param graph 图指针
 */
void find_star_structures(Graph* graph);

/**
 * ACL检查功能：检查Target IP与目标范围的访问规则
 * @param graph 图指针
 * @param target_ip 源IP
 * @param start_ip 目标范围起始IP
 * @param end_ip 目标范围结束IP
 * @param is_allow_rule 1=Allow, 0=Deny
 */
void check_acl(Graph* graph, const char* target_ip, const char* start_ip, const char* end_ip, int is_allow_rule);

#endif // ANALYSIS_H
