/**
 * 网络流量分析系统 - 流量分析模块实现
 */

#include "../include/analysis.h"
#include "../include/hash.h"
#include <inttypes.h>

// 快速排序辅助结构体
typedef struct {
    int index;
    long long total_traffic;
    double ratio;
} NodeStat;

// 快排比较函数（降序）
static int cmp_node_stat(const void* a, const void* b) {
    const NodeStat* na = (const NodeStat*)a;
    const NodeStat* nb = (const NodeStat*)b;
    if (nb->total_traffic > na->total_traffic) return 1;
    if (nb->total_traffic < na->total_traffic) return -1;
    return 0;
}

// 节点流量排序 - 仅显示有流量的节点
void sort_nodes_by_traffic(Graph* graph, int top_n) {
    int n = graph->node_count, cnt = 0;
    NodeStat* stats = (NodeStat*)malloc(sizeof(NodeStat) * n);

    for (int i = 0; i < n; ++i) {
        long long total = graph->nodes[i].in_traffic + graph->nodes[i].out_traffic;
        if (total > 0) {
            stats[cnt].index = i;
            stats[cnt].total_traffic = total;
            cnt++;
        }
    }

    qsort(stats, cnt, sizeof(NodeStat), cmp_node_stat);

    printf("\n[All Nodes Sorted by Traffic (Total: %d)]\n", cnt);
    printf("%-6s %-16s %-16s %-16s %-16s\n", "Rank", "IP", "Inbound", "Outbound", "Total");

    int limit = top_n > 0 ? (top_n < cnt ? top_n : cnt) : cnt;
    for (int i = 0; i < limit; ++i) {
        int idx = stats[i].index;
        printf("%-6d %-16s %-16I64d %-16I64d %-16I64d\n",
            i + 1,
            graph->nodes[idx].ip,
            graph->nodes[idx].in_traffic,
            graph->nodes[idx].out_traffic,
            stats[i].total_traffic);
    }

    free(stats);
}

 

void https_nodes_sorted_by_total(Graph* graph) {
    int n = graph->node_count, cnt = 0;
    NodeStat* stats = (NodeStat*)malloc(sizeof(NodeStat) * n);
    for (int i = 0; i < n; ++i) {
        if (graph->nodes[i].https_traffic > 0) {
            stats[cnt].index = i;
            stats[cnt].total_traffic = graph->nodes[i].in_traffic + graph->nodes[i].out_traffic;
            cnt++;
        }
    }
    qsort(stats, cnt, sizeof(NodeStat), cmp_node_stat);
    printf("\n[All HTTPS Nodes Sorted by Total Traffic (Total: %d)]\n", cnt);
    printf("%-6s %-16s %-16s %-16s %-16s %-16s\n", "Rank", "IP", "Inbound", "Outbound", "HTTPS", "Total");
    for (int i = 0; i < cnt; ++i) {
        int idx = stats[i].index;
        printf("%-6d %-16s %-16I64d %-16I64d %-16I64d %-16I64d\n",
            i + 1,
            graph->nodes[idx].ip,
            graph->nodes[idx].in_traffic,
            graph->nodes[idx].out_traffic,
            graph->nodes[idx].https_traffic,
            graph->nodes[idx].in_traffic + graph->nodes[idx].out_traffic);
    }
    free(stats);
}

void https_nodes_sorted_by_https(Graph* graph) {
    int n = graph->node_count, cnt = 0;
    NodeStat* stats = (NodeStat*)malloc(sizeof(NodeStat) * n);
    for (int i = 0; i < n; ++i) {
        if (graph->nodes[i].https_traffic > 0) {
            stats[cnt].index = i;
            stats[cnt].total_traffic = graph->nodes[i].https_traffic;
            cnt++;
        }
    }
    qsort(stats, cnt, sizeof(NodeStat), cmp_node_stat);
    printf("\n[All HTTPS Nodes Sorted by HTTPS Traffic (Total: %d)]\n", cnt);
    printf("%-6s %-16s %-16s %-16s %-16s %-16s\n", "Rank", "IP", "Inbound", "Outbound", "HTTPS", "Total");
    for (int i = 0; i < cnt; ++i) {
        int idx = stats[i].index;
        printf("%-6d %-16s %-16I64d %-16I64d %-16I64d %-16I64d\n",
            i + 1,
            graph->nodes[idx].ip,
            graph->nodes[idx].in_traffic,
            graph->nodes[idx].out_traffic,
            graph->nodes[idx].https_traffic,
            graph->nodes[idx].in_traffic + graph->nodes[idx].out_traffic);
    }
    free(stats);
}
// 单向发出流量占比 > 80% 的节点筛选
void filter_suspicious_nodes(Graph* graph, int top_n) {
    int n = graph->node_count, cnt = 0;
    NodeStat* stats = (NodeStat*)malloc(sizeof(NodeStat) * n);

    for (int i = 0; i < n; ++i) {
        long long in_ = graph->nodes[i].in_traffic;
        long long out_ = graph->nodes[i].out_traffic;
        long long total = in_ + out_;
        if (total == 0) continue;

        double ratio = (double)out_ / total;
        if (ratio > 0.8) {
            stats[cnt].index = i;
            stats[cnt].total_traffic = total;
            stats[cnt].ratio = ratio;
            cnt++;
        }
    }

    qsort(stats, cnt, sizeof(NodeStat), cmp_node_stat);

    printf("\n[Top %d Suspicious Port Scan Nodes]\n", top_n);
    printf("%-16s %-16s %-16s %-16s\n", "IP", "Total", "Outbound", "Outbound Ratio");

    for (int i = 0; i < cnt && i < top_n; ++i) {
        int idx = stats[i].index;
        printf("%-16s %-16I64d %-16I64d %8.2f%%\n",
            graph->nodes[idx].ip,
            stats[i].total_traffic,
            graph->nodes[idx].out_traffic,
            stats[i].ratio * 100);
    }

    free(stats);
}

// Find all star structures in the network graph
void find_star_structures(Graph* graph) {
    int n = graph->node_count;
    int min_star_size = 20;
    int found = 0;
    printf("\n[Star Structures in Network Graph]\n");
    for (int i = 0; i < n; ++i) {
        Node* center = &graph->nodes[i];
        int star_count = 0;
        int direct_count = 0;
        int* star_indices = (int*)malloc(sizeof(int) * n); // max possible
        Edge* edge = center->edges;
        while (edge) {
            int neighbor_idx = edge->dest_index;
            direct_count++;
            // 判断邻居节点的入度是否为1，且唯一入度来自中心节点
            int in_degree = 0;
            int from_center = 0;
            for (int m = 0; m < n; ++m) {
                Edge* e3 = graph->nodes[m].edges;
                while (e3) {
                    if (e3->dest_index == neighbor_idx) {
                        in_degree++;
                        if (m == i) from_center = 1;
                    }
                    e3 = e3->next;
                }
            }
            if (in_degree == 1 && from_center == 1) {
                star_indices[star_count++] = neighbor_idx;
            }
            edge = edge->next;
        }
        if (star_count >= min_star_size) {
            found++;
            printf("Center node %s | Direct neighbors: %d | Exclusive neighbors: %d\n", center->ip, direct_count, star_count);
            printf("Exclusive list: ");
            for (int k = 0; k < star_count; ++k) {
                printf("%s", graph->nodes[star_indices[k]].ip);
                if (k < star_count - 1) printf(", ");
            }
            printf("\n");
        }
        free(star_indices);
    }
    if (found == 0) {
        printf("No star structures found (center node with >=%d exclusive neighbors).\n", min_star_size);
    } else {
        printf("Total star structures found: %d\n", found);
    }
}

// 辅助函数：将IPv4字符串转为32位整数
unsigned int ip_to_uint(const char* ip) {
    unsigned int b1, b2, b3, b4;
    sscanf(ip, "%u.%u.%u.%u", &b1, &b2, &b3, &b4);
    return (b1 << 24) | (b2 << 16) | (b3 << 8) | b4;
}

// ACL检查功能：检查Target IP与目标范围的访问规则
void check_acl(Graph* graph, const char* target_ip, const char* start_ip, const char* end_ip, int is_allow_rule) {
    int target_idx = find_ip_index(graph, target_ip);
    if (target_idx == -1) {
        printf("[ACL] Target IP %s not found in graph!\n", target_ip);
        return;
    }
    unsigned int start_val = ip_to_uint(start_ip);
    unsigned int end_val = ip_to_uint(end_ip);
    printf("[ACL] Violations for rule (%s):\n", is_allow_rule ? "Allow" : "Deny");
    int violation_count = 0;
    Edge* edge = graph->nodes[target_idx].edges;
    while (edge) {
        const char* dst_ip = graph->nodes[edge->dest_index].ip;
        unsigned int ip_val = ip_to_uint(dst_ip);
        int in_range = (ip_val >= start_val && ip_val <= end_val);
        if ((is_allow_rule && !in_range) || (!is_allow_rule && in_range)) {
            printf("  %s -> %s, Traffic: %llu bytes\n", target_ip, dst_ip, (unsigned long long)edge->total_data_size);
            violation_count++;
        }
        edge = edge->next;
    }
    if (violation_count == 0) {
        printf("  No violations found.\n");
    }
}

// 流量排行分析（便捷接口）
void analyze_traffic_ranking(Graph* graph, int top_n) {
    sort_nodes_by_traffic(graph, top_n);
}

// 协议流量分析（便捷接口）
void analyze_protocol_traffic(Graph* graph, const char* protocol) {
    if (strcmp(protocol, "HTTPS") == 0) {
        https_nodes_sorted_by_total(graph);
    } else {
        printf("Protocol analysis not supported yet\n");
    }
}

// 异常节点检测（便捷接口）
void detect_anomaly_nodes(Graph* graph, double threshold) {
    filter_suspicious_nodes(graph, 20);
    (void)threshold; // 标记参数已使用
}
