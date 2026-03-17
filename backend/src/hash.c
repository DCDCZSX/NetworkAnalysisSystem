/**
 * 网络流量分析系统 - 哈希表模块实现
 */

#include "../include/hash.h"

// BKDR Hash 算法实现
unsigned int hash_function(const char* ip) {
    unsigned int seed = 131;
    unsigned int hash = 0;
    while (*ip) {
        hash = hash * seed + (*ip++);
    }
    return (hash & 0x7FFFFFFF) % HASH_TABLE_SIZE;
}

// 在哈希表中查找 IP 对应的节点索引
int find_ip_index(Graph* graph, const char* ip) {
    unsigned int hash = hash_function(ip);
    HashNode* node = graph->hash_table[hash];
    while (node) {
        if (strcmp(node->ip, ip) == 0) {
            return node->index;
        }
        node = node->next;
    }
    return -1;
}

// 添加 IP 到图中
int add_ip_to_graph(Graph* graph, const char* ip) {
    int idx = find_ip_index(graph, ip);
    if (idx != -1) return idx;

    if (graph->node_count >= MAX_NODES) {
        fprintf(stderr, "Node count exceeds maximum limit!\n");
        exit(EXIT_FAILURE);
    }

    int new_idx = graph->node_count++;
    strncpy(graph->nodes[new_idx].ip, ip, MAX_IP_LENGTH);
    graph->nodes[new_idx].ip[MAX_IP_LENGTH-1] = '\0';
    graph->nodes[new_idx].in_traffic = 0;
    graph->nodes[new_idx].out_traffic = 0;
    graph->nodes[new_idx].https_traffic = 0;
    graph->nodes[new_idx].edges = NULL;

    // 插入哈希表
    unsigned int hash = hash_function(ip);
    HashNode* new_node = (HashNode*)malloc(sizeof(HashNode));
    strncpy(new_node->ip, ip, MAX_IP_LENGTH);
    new_node->ip[MAX_IP_LENGTH-1] = '\0';
    new_node->index = new_idx;
    new_node->next = graph->hash_table[hash];
    graph->hash_table[hash] = new_node;

    return new_idx;
}
