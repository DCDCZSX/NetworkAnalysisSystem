/**
 * 网络流量分析系统 - 路径查找算法模块实现
 */

#include "../include/algorithm.h"
#include "../include/hash.h"
#include <float.h>

/*******************************
 * BFS 算法实现
 *******************************/

// BFS 路径查找 - 跳数最少
Path* bfs_shortest_path(Graph* graph, const char* src_ip, const char* dst_ip) {
    int src_idx = find_ip_index(graph, src_ip);
    int dst_idx = find_ip_index(graph, dst_ip);
    if (src_idx == -1 || dst_idx == -1) return NULL;

    int n = graph->node_count;
    int* visited = (int*)calloc(n, sizeof(int));
    int* prev = (int*)malloc(sizeof(int) * n);
    for (int i = 0; i < n; ++i) prev[i] = -1;

    int* queue = (int*)malloc(sizeof(int) * n);
    int front = 0, rear = 0;

    visited[src_idx] = 1;
    queue[rear++] = src_idx;
    int found = 0;

    while (front < rear) {
        int u = queue[front++];
        if (u == dst_idx) {
            found = 1;
            break;
        }

        for (Edge* e = graph->nodes[u].edges; e; e = e->next) {
            int v = e->dest_index;
            if (!visited[v]) {
                visited[v] = 1;
                prev[v] = u;
                queue[rear++] = v;
            }
        }
    }

    Path* path = NULL;
    if (found) {
        // 回溯路径
        int len = 0, cur = dst_idx;
        while (cur != -1) {
            ++len;
            cur = prev[cur];
        }

        path = (Path*)malloc(sizeof(Path));
        path->nodes = (int*)malloc(sizeof(int) * len);
        path->length = len;
        path->weight = 0;

        cur = dst_idx;
        for (int i = len - 1; i >= 0; --i) {
            path->nodes[i] = cur;
            cur = prev[cur];
        }
    }

    free(visited);
    free(prev);
    free(queue);
    return path;
}

/*******************************
 * 优先队列实现
 *******************************/

// 创建优先队列
PriorityQueue* create_priority_queue(int capacity) {
    PriorityQueue* pq = (PriorityQueue*)malloc(sizeof(PriorityQueue));
    pq->nodes = (PQNode*)malloc(sizeof(PQNode) * capacity);
    pq->size = 0;
    pq->capacity = capacity;
    return pq;
}

// 释放优先队列
void free_priority_queue(PriorityQueue* pq) {
    if (!pq) return;
    free(pq->nodes);
    free(pq);
}

// 上浮调整
static void pq_up(PriorityQueue* pq, int idx) {
    while (idx > 0) {
        int parent = (idx - 1) / 2;
        if (pq->nodes[parent].distance <= pq->nodes[idx].distance) break;

        PQNode tmp = pq->nodes[parent];
        pq->nodes[parent] = pq->nodes[idx];
        pq->nodes[idx] = tmp;
        idx = parent;
    }
}

// 下沉调整
static void pq_down(PriorityQueue* pq, int idx) {
    int n = pq->size;
    while (1) {
        int l = idx * 2 + 1;
        int r = idx * 2 + 2;
        int min_idx = idx;

        if (l < n && pq->nodes[l].distance < pq->nodes[min_idx].distance)
            min_idx = l;
        if (r < n && pq->nodes[r].distance < pq->nodes[min_idx].distance)
            min_idx = r;

        if (min_idx == idx) break;

        PQNode tmp = pq->nodes[min_idx];
        pq->nodes[min_idx] = pq->nodes[idx];
        pq->nodes[idx] = tmp;
        idx = min_idx;
    }
}

// 插入元素
void pq_push(PriorityQueue* pq, int vertex, double distance) {
    if (pq->size >= pq->capacity) return;

    pq->nodes[pq->size].vertex = vertex;
    pq->nodes[pq->size].distance = distance;
    pq_up(pq, pq->size);
    pq->size++;
}

// 弹出最小元素
PQNode pq_pop(PriorityQueue* pq) {
    PQNode ret = pq->nodes[0];
    pq->nodes[0] = pq->nodes[--pq->size];
    pq_down(pq, 0);
    return ret;
}

// 判断是否为空
int pq_is_empty(PriorityQueue* pq) {
    return pq->size == 0;
}

/*******************************
 * Dijkstra 算法实现
 *******************************/

// Dijkstra 路径查找 - 拥塞程度最小
Path* dijkstra_least_congestion_path(Graph* graph, const char* src_ip, const char* dst_ip) {
    int src_idx = find_ip_index(graph, src_ip);
    int dst_idx = find_ip_index(graph, dst_ip);
    if (src_idx == -1 || dst_idx == -1) return NULL;

    int n = graph->node_count;
    double* dist = (double*)malloc(sizeof(double) * n);
    int* prev = (int*)malloc(sizeof(int) * n);

    for (int i = 0; i < n; ++i) {
        dist[i] = DBL_MAX;
        prev[i] = -1;
    }

    dist[src_idx] = 0;
    PriorityQueue* pq = create_priority_queue(n);
    pq_push(pq, src_idx, 0);

    while (!pq_is_empty(pq)) {
        PQNode node = pq_pop(pq);
        int u = node.vertex;

        if (u == dst_idx) break;

        for (Edge* e = graph->nodes[u].edges; e; e = e->next) {
            int v = e->dest_index;
            // 拥塞程度 = 流量 / 时长
            double weight = (e->total_duration > 0) ?
                ((double)e->total_data_size / e->total_duration) : DBL_MAX;

            if (dist[u] + weight < dist[v]) {
                dist[v] = dist[u] + weight;
                prev[v] = u;
                pq_push(pq, v, dist[v]);
            }
        }
    }

    Path* path = NULL;
    if (dist[dst_idx] < DBL_MAX) {
        // 回溯路径
        int len = 0, cur = dst_idx;
        while (cur != -1) {
            ++len;
            cur = prev[cur];
        }

        path = (Path*)malloc(sizeof(Path));
        path->nodes = (int*)malloc(sizeof(int) * len);
        path->length = len;
        path->weight = dist[dst_idx];

        cur = dst_idx;
        for (int i = len - 1; i >= 0; --i) {
            path->nodes[i] = cur;
            cur = prev[cur];
        }
    }

    free(dist);
    free(prev);
    free_priority_queue(pq);
    return path;
}

/*******************************
 * 路径打印与内存释放
 *******************************/

// 打印路径
void print_path(Graph* graph, Path* path, const char* path_type, int show_weight) {
    if (!path) {
        printf("%s: Path not found\n", path_type);
        return;
    }
    // 路径长度 = 边数 = 节点数 - 1
    int edge_count = path->length > 0 ? path->length - 1 : 0;
    if (show_weight) {
        printf("%s: Path length = %d, Congestion weight = %.4f\n", path_type, edge_count, path->weight);
    } else {
        printf("%s: Path length = %d\n", path_type, edge_count);
    }
    for (int i = 0; i < path->length; ++i) {
        printf("%s", graph->nodes[path->nodes[i]].ip);
        if (i < path->length - 1) printf(" -> ");
    }
    printf("\n");
}

// 释放路径内存
void free_path(Path* path) {
    if (!path) return;
    free(path->nodes);
    free(path);
}

/*******************************
 * 便捷接口实现
 *******************************/

// BFS路径查找（打印版本）
void find_path_bfs(Graph* graph, const char* src_ip, const char* dst_ip) {
    Path* path = bfs_shortest_path(graph, src_ip, dst_ip);
    if (path) {
        print_path(graph, path, "BFS Shortest Path", 0); // 只输出最短路径长度
        free_path(path);
    } else {
        printf("No path found from %s to %s\n", src_ip, dst_ip);
    }
}

// Dijkstra路径查找（打印版本）
void find_path_dijkstra(Graph* graph, const char* src_ip, const char* dst_ip) {
    Path* path = dijkstra_least_congestion_path(graph, src_ip, dst_ip);
    if (path) {
        print_path(graph, path, "Dijkstra Minimum Congestion Path", 1); // 输出拥塞权重和长度
        free_path(path);
    } else {
        printf("No path found from %s to %s\n", src_ip, dst_ip);
    }
}
