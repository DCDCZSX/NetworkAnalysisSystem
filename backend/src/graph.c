/**
 * 网络流量分析系统 - 图操作模块实现
 */

#include "../include/graph.h"
#include "../include/hash.h"

static unsigned int be16(const unsigned char* p);
static unsigned int be32(const unsigned char* p);
static unsigned int le32(const unsigned char* p);
static unsigned int be16(const unsigned char* p) { return (p[0] << 8) | p[1]; }
static unsigned int be32(const unsigned char* p) { return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]; }
static unsigned int le32(const unsigned char* p) { return (p[3] << 24) | (p[2] << 16) | (p[1] << 8) | p[0]; }
// 创建图
Graph* create_graph() {
    Graph* graph = (Graph*)malloc(sizeof(Graph));
    graph->node_count = 0;
    for (int i = 0; i < HASH_TABLE_SIZE; ++i) {
        graph->hash_table[i] = NULL;
    }
    return graph;
}

int load_data_from_pcapng(Graph* graph, const char* filename) {
    FILE* fp = fopen(filename, "rb");
    if (!fp) return -1;
    unsigned int linktype = 1;
    while (1) {
        unsigned char hdr[8];
        size_t r = fread(hdr, 1, 8, fp);
        if (r == 0) break;
        if (r != 8) { fclose(fp); return -1; }
        unsigned int block_type = le32(hdr);
        unsigned int block_len = le32(hdr + 4);
        if (block_len < 12) { fclose(fp); return -1; }
        unsigned int content_len = block_len - 12;
        unsigned char* buf = (unsigned char*)malloc(content_len);
        if (!buf) { fclose(fp); return -1; }
        if (fread(buf, 1, content_len, fp) != content_len) { free(buf); fclose(fp); return -1; }
        unsigned char tail[4];
        if (fread(tail, 1, 4, fp) != 4) { free(buf); fclose(fp); return -1; }

        if (block_type == 0x00000001) {
            if (content_len >= 8) {
                linktype = buf[0] | (buf[1] << 8);
            }
        } else if (block_type == 0x00000006) {
            if (content_len >= 20) {
                unsigned int cap_len = le32(buf + 12);
                if (cap_len > 0 && cap_len <= content_len - 20) {
                    const unsigned char* pkt = buf + 20;
                    unsigned int incl_len = cap_len;

                    if (linktype == 1 && incl_len >= 14) {
                        unsigned int eth_type = be16(pkt + 12);
                        if (eth_type == 0x0800) {
                            unsigned int ip_off = 14;
                            if (incl_len >= ip_off + 20) {
                                unsigned char vihl = pkt[ip_off];
                                unsigned int ihl = (vihl & 0x0F) * 4;
                                if (incl_len >= ip_off + ihl) {
                                    unsigned int total_len = be16(pkt + ip_off + 2);
                                    unsigned int proto = pkt[ip_off + 9];
                                    unsigned char srcb[4], dstb[4];
                                    memcpy(srcb, pkt + ip_off + 12, 4);
                                    memcpy(dstb, pkt + ip_off + 16, 4);
                                    char src_ip[16], dst_ip[16];
                                    snprintf(src_ip, sizeof(src_ip), "%u.%u.%u.%u", srcb[0], srcb[1], srcb[2], srcb[3]);
                                    snprintf(dst_ip, sizeof(dst_ip), "%u.%u.%u.%u", dstb[0], dstb[1], dstb[2], dstb[3]);
                                    unsigned int l4_off = ip_off + ihl;
                                    int src_port = 0, dst_port = 0;
                                    long long payload = 0;
                                    if (proto == PROTOCOL_TCP) {
                                        if (incl_len >= l4_off + 20) {
                                            src_port = be16(pkt + l4_off);
                                            dst_port = be16(pkt + l4_off + 2);
                                            unsigned int data_offset = (pkt[l4_off + 12] >> 4) * 4;
                                            if (ihl + data_offset <= total_len) {
                                                payload = (long long)(total_len - ihl - data_offset);
                                            }
                                        }
                                    } else if (proto == PROTOCOL_UDP) {
                                        if (incl_len >= l4_off + 8) {
                                            src_port = be16(pkt + l4_off);
                                            dst_port = be16(pkt + l4_off + 2);
                                            unsigned int udp_len = be16(pkt + l4_off + 4);
                                            if (udp_len >= 8) payload = (long long)(udp_len - 8);
                                        }
                                    }
                                    if (payload > 0) {
                                        add_or_update_edge(graph, src_ip, dst_ip, proto, src_port, dst_port, payload, 1);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        free(buf);
    }
    fclose(fp);
    return 0;
}
// 释放图的所有内存
void free_graph(Graph* graph) {
    if (!graph) return;

    // 释放所有边
    for (int i = 0; i < graph->node_count; ++i) {
        Edge* edge = graph->nodes[i].edges;
        while (edge) {
            Edge* tmp = edge;
            edge = edge->next;
            free(tmp);
        }
    }

    // 释放哈希表
    for (int i = 0; i < HASH_TABLE_SIZE; ++i) {
        HashNode* node = graph->hash_table[i];
        while (node) {
            HashNode* tmp = node;
            node = node->next;
            free(tmp);
        }
    }

    free(graph);
}

// destroy_graph - free_graph 的别名
void destroy_graph(Graph* graph) {
    free_graph(graph);
}

// 添加或更新边
void add_or_update_edge(Graph* graph, const char* src_ip, const char* dst_ip,
                        int protocol, int src_port, int dst_port, long long data_size, long long duration) {
    int src_idx = add_ip_to_graph(graph, src_ip);
    int dst_idx = add_ip_to_graph(graph, dst_ip);

    // 更新节点流量统计
    graph->nodes[src_idx].out_traffic += data_size;
    graph->nodes[dst_idx].in_traffic += data_size;

    // 如果是 HTTPS 流量：仅计入目标节点（DstPort=443且Protocol=TCP）
    if (protocol == PROTOCOL_TCP && (dst_port == HTTPS_PORT || src_port == HTTPS_PORT)) {
        graph->nodes[src_idx].https_traffic += data_size;
        graph->nodes[dst_idx].https_traffic += data_size;
    }

    // 查找是否已存在该边
    Edge* edge = graph->nodes[src_idx].edges;
    while (edge) {
        if (edge->dest_index == dst_idx) {
            edge->total_data_size += data_size;
            edge->total_duration += duration;
            if (protocol == PROTOCOL_TCP && (dst_port == HTTPS_PORT || src_port == HTTPS_PORT)) {
                edge->https_data_size += data_size;
            }
            return;
        }
        edge = edge->next;
    }

    // 创建新边
    Edge* new_edge = (Edge*)malloc(sizeof(Edge));
    new_edge->dest_index = dst_idx;
    new_edge->total_data_size = data_size;
    new_edge->total_duration = duration;
    new_edge->https_data_size = (protocol == PROTOCOL_TCP && (dst_port == HTTPS_PORT || src_port == HTTPS_PORT)) ? data_size : 0;
    new_edge->next = graph->nodes[src_idx].edges;
    graph->nodes[src_idx].edges = new_edge;
}

// 添加边（简化版接口）
void add_edge(Graph* graph, const char* src_ip, const char* dst_ip,
              const char* protocol, int bytes) {
    int proto = PROTOCOL_TCP;
    int src_port = 0;
    int dst_port = 80;

    if (strcmp(protocol, "HTTPS") == 0) {
        dst_port = 443;
        src_port = 443;
    } else if (strcmp(protocol, "SSH") == 0) {
        dst_port = 22;
    } else if (strcmp(protocol, "FTP") == 0) {
        dst_port = 21;
    } else if (strcmp(protocol, "DNS") == 0) {
        dst_port = 53;
        proto = PROTOCOL_UDP;
    } else if (strcmp(protocol, "SMTP") == 0) {
        dst_port = 25;
    }

    add_or_update_edge(graph, src_ip, dst_ip, proto, src_port, dst_port, bytes, 1);
}

// 查找节点
Node* find_node(Graph* graph, const char* ip) {
    int idx = find_ip_index(graph, ip);
    if (idx == -1) return NULL;
    return &graph->nodes[idx];
}

// 从CSV文件读取数据
int load_data_from_csv(Graph* graph, const char* filename) {
    FILE* fp = fopen(filename, "r");
    if (!fp) {
        perror("Failed to open CSV file");
        return -1;
    }

    char line[256];
    fgets(line, sizeof(line), fp); // skip header

    while (fgets(line, sizeof(line), fp)) {
        char fields_raw[7][64];
        for (int k = 0; k < 7; ++k) { fields_raw[k][0] = '\0'; }
        int fcount = 0, pos = 0;
        for (const char* p = line; *p; ++p) {
            if (*p == ',' || *p == '\n' || *p == '\r') {
                if (fcount < 7) {
                    fields_raw[fcount][pos] = '\0';
                    fcount++;
                    pos = 0;
                }
                if (*p == ',' && fcount >= 7) break;
            } else {
                if (fcount < 7 && pos < (int)sizeof(fields_raw[0]) - 1) {
                    fields_raw[fcount][pos++] = *p;
                }
            }
        }
        if (pos > 0 && fcount < 7) {
            fields_raw[fcount][pos] = '\0';
            fcount++;
        }
        char* fields[7];
        for (int k = 0; k < fcount && k < 7; ++k) fields[k] = fields_raw[k];

        // 仅在存在有效数据时再创建节点（避免出现零流量节点）

        if (fcount >= 6) {
            const char* src_ip = fields[0];
            const char* dst_ip = fields[1];
            int protocol_num = atoi(fields[2]);
            int src_port = (fields[3] && fields[3][0]) ? atoi(fields[3]) : 0;
            int dst_port = (fields[4] && fields[4][0]) ? atoi(fields[4]) : 0;
            long long data_size = atoll(fields[5]);
            long long duration = (fcount >= 7) ? atoll(fields[6]) : 1;
            add_or_update_edge(graph, src_ip, dst_ip, protocol_num, src_port, dst_port, data_size, duration);
        } else if (fcount == 4) {
            const char* src_ip = fields[0];
            const char* dst_ip = fields[1];
            const char* protocol_str = fields[2];
            long long bytes_ll = atoll(fields[3]);
            add_edge(graph, src_ip, dst_ip, protocol_str, (int)bytes_ll);
        }
    }

    fclose(fp);
    return 0;
}

// 导出网络图到CSV
void export_network_graph_csv(Graph* graph, const char* filename) {
    FILE* fp = fopen(filename, "w");
    if (!fp) {
        perror("Failed to create output file");
        return;
    }

    fprintf(fp, "src_ip,dst_ip,total_bytes,total_duration,https_bytes\n");

    for (int i = 0; i < graph->node_count; ++i) {
        Edge* edge = graph->nodes[i].edges;
        while (edge) {
            fprintf(fp, "%s,%s,%I64d,%I64d,%I64d\n",
                graph->nodes[i].ip,
                graph->nodes[edge->dest_index].ip,
                edge->total_data_size,
                edge->total_duration,
                edge->https_data_size);
            edge = edge->next;
        }
    }

    fclose(fp);
    printf("Network graph exported to: %s\n", filename);
}
