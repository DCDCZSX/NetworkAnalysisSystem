/*
 * Network Traffic Analyzer - CLI Version for Tauri Integration
 * Accepts command-line arguments and outputs JSON format
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#endif
#include "graph.h"
#include "analysis.h"
#include "algorithm.h"

void print_usage() {
    printf("Usage: network_analyzer_cli <command> [options]\n");
    printf("Commands:\n");
    printf("  load <csv_file>              - Load data and build graph\n");
    printf("  top10 <csv_file>             - Show top 10 nodes by traffic\n");
    printf("  https <csv_file>             - Show HTTPS traffic ranking\n");
    printf("  anomaly <csv_file> [ratio]   - Detect anomaly nodes (default ratio: 0.8)\n");
    printf("  path <csv_file> <src> <dst>  - Find paths between two IPs\n");
}

int main(int argc, char* argv[]) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif

    if (argc < 2) {
        print_usage();
        return 1;
    }

    const char* command = argv[1];

    if (strcmp(command, "load") == 0) {
        if (argc < 3) {
            fprintf(stderr, "{\"error\": \"Missing CSV file parameter\"}\n");
            return 1;
        }
        Graph* g = create_graph();
        int ret = load_data_from_csv(g, argv[2]);
        if (ret != 0) {
            fprintf(stderr, "{\"error\": \"Cannot open file: %s\"}\n", argv[2]);
            destroy_graph(g);
            return 1;
        }
        printf("{\"success\": true, \"node_count\": %d}\n", g->node_count);
        destroy_graph(g);

    } else if (strcmp(command, "top10") == 0) {
        if (argc < 3) {
            fprintf(stderr, "{\"error\": \"Missing CSV file parameter\"}\n");
            return 1;
        }
        Graph* g = create_graph();
        if (load_data_from_csv(g, argv[2]) != 0) {
            fprintf(stderr, "{\"error\": \"Cannot open file: %s\"}\n", argv[2]);
            destroy_graph(g);
            return 1;
        }
        analyze_traffic_ranking(g, 10);
        destroy_graph(g);

    } else if (strcmp(command, "https") == 0) {
        if (argc < 3) {
            fprintf(stderr, "{\"error\": \"Missing CSV file parameter\"}\n");
            return 1;
        }
        Graph* g = create_graph();
        if (load_data_from_csv(g, argv[2]) != 0) {
            fprintf(stderr, "{\"error\": \"Cannot open file: %s\"}\n", argv[2]);
            destroy_graph(g);
            return 1;
        }
        analyze_protocol_traffic(g, "HTTPS");
        destroy_graph(g);

    } else if (strcmp(command, "anomaly") == 0) {
        if (argc < 3) {
            fprintf(stderr, "{\"error\": \"Missing CSV file parameter\"}\n");
            return 1;
        }
        double ratio = 0.8;
        if (argc >= 4) {
            ratio = atof(argv[3]);
        }
        Graph* g = create_graph();
        if (load_data_from_csv(g, argv[2]) != 0) {
            fprintf(stderr, "{\"error\": \"Cannot open file: %s\"}\n", argv[2]);
            destroy_graph(g);
            return 1;
        }
        detect_anomaly_nodes(g, ratio);
        destroy_graph(g);

    } else if (strcmp(command, "path") == 0) {
        if (argc < 5) {
            fprintf(stderr, "{\"error\": \"Missing parameters. Usage: path <csv_file> <src_ip> <dst_ip>\"}\n");
            return 1;
        }
        Graph* g = create_graph();
        if (load_data_from_csv(g, argv[2]) != 0) {
            fprintf(stderr, "{\"error\": \"Cannot open file: %s\"}\n", argv[2]);
            destroy_graph(g);
            return 1;
        }
        const char* src_ip = argv[3];
        const char* dst_ip = argv[4];
        Node* src = find_node(g, src_ip);
        Node* dst = find_node(g, dst_ip);
        if (src == NULL) {
            fprintf(stderr, "{\"error\": \"Source IP %s not found\"}\n", src_ip);
            destroy_graph(g);
            return 1;
        }
        if (dst == NULL) {
            fprintf(stderr, "{\"error\": \"Destination IP %s not found\"}\n", dst_ip);
            destroy_graph(g);
            return 1;
        }
        printf("{\"bfs\": ");
        find_path_bfs(g, src_ip, dst_ip);
        printf(", \"dijkstra\": ");
        find_path_dijkstra(g, src_ip, dst_ip);
        printf("}\n");
        destroy_graph(g);

    } else {
        fprintf(stderr, "{\"error\": \"Unknown command: %s\"}\n", command);
        print_usage();
        return 1;
    }

    return 0;
}
