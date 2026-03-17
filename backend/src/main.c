/*
 * Network Traffic Analysis & Anomaly Detection System - Main Program
 * Provides an interactive command-line menu and calls various graph analysis functions
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/graph.h"
#include "../include/analysis.h"
#include "../include/algorithm.h"

// Global graph structure pointer
Graph* g = NULL;

// Print main menu
void print_menu() {
    printf("\n");
    printf("========================================\n");
    printf("   Network Traffic Analysis & Anomaly Detection v1.0\n");
    printf("========================================\n");
    printf("[1] Load network flow data and build graph\n");
    printf("[2] View all nodes sorted by traffic\n");
    printf("[3] View all HTTPS nodes sorted by traffic\n");
    printf("[4] Anomaly detection: suspicious port scan nodes\n");
    printf("[5] Path search and congestion analysis\n");
    printf("[6] Find star structures in the network graph\n");
    printf("[7] ACL access control check\n");
    printf("[8] Load CSV from local file path\n");
    printf("[9] HTTPS ranking by Total Traffic\n");
    printf("[10] HTTPS ranking by HTTPS Traffic\n");
    printf("[11] Filter nodes with >80%% unidirectional traffic\n");
    printf("[0] Exit\n");
    printf("========================================\n");
    printf("Please enter your choice: ");
    fflush(stdout);
}

// Check if the graph is ready
int check_graph_ready() {
    if (g == NULL) {
        printf("\n[Error] Please load data and build the graph first!\n");
        return 0;
    }
    return 1;
}

// Option 1: Load data and build graph
void option_load_data() {
    if (g != NULL) {
        printf("\n[Info] Existing graph detected, releasing old data...\n");
        destroy_graph(g);
        g = NULL;
    }

    printf("\nLoading data/network_data.csv and building graph...\n");
    g = create_graph();

    if (load_data_from_csv(g, "data/network_data.csv") == 0) {
        printf("[Success] Graph built successfully!\n");
        printf("[Info] Current graph has %d nodes\n", g->node_count);
    } else {
        printf("[Error] Data loading failed!\n");
        destroy_graph(g);
        g = NULL;
    }
}

void option_load_data_custom() {
    if (g != NULL) {
        printf("\n[Info] Existing graph detected, releasing old data...\n");
        destroy_graph(g);
        g = NULL;
    }
    char path[512];
    printf("\nEnter data file path: ");
    fflush(stdout);
    if (!fgets(path, sizeof(path), stdin)) {
        printf("[Error] Failed to read path\n");
        return;
    }
    size_t len = strlen(path);
    if (len > 0 && (path[len-1] == '\n' || path[len-1] == '\r')) {
        path[len-1] = '\0';
        if (len > 1 && path[len-2] == '\r') path[len-2] = '\0';
    }
    if (path[0] == '\0') {
        printf("[Error] Empty path\n");
        return;
    }
    g = create_graph();
    const char* ext_csv = ".csv";
    const char* ext_pcapng = ".pcapng";
    size_t plen = strlen(path);
    int ok = -1;
    if (plen >= strlen(ext_csv) && strcasecmp(path + plen - strlen(ext_csv), ext_csv) == 0) {
        ok = load_data_from_csv(g, path);
    } else if (plen >= strlen(ext_pcapng) && strcasecmp(path + plen - strlen(ext_pcapng), ext_pcapng) == 0) {
        ok = load_data_from_pcapng(g, path);
    } else {
        ok = load_data_from_csv(g, path);
    }
    if (ok == 0) {
        printf("[Success] Graph built successfully!\n");
        printf("[Info] Current graph has %d nodes\n", g->node_count);
    } else {
        printf("[Error] Data loading failed!\n");
        destroy_graph(g);
        g = NULL;
    }
}

// Option 2: Traffic ranking
void option_traffic_ranking() {
    if (!check_graph_ready()) return;

    printf("\n========== All Nodes Sorted by Traffic ==========\n");
    analyze_traffic_ranking(g, 10);
}

// Option 3: HTTPS traffic ranking
void option_https_ranking() {
    if (!check_graph_ready()) return;

    printf("\n========== All HTTPS Nodes Sorted by Traffic ==========\n");
    analyze_protocol_traffic(g, "HTTPS");
}

void option_https_ranking_total() {
    if (!check_graph_ready()) return;
    https_nodes_sorted_by_total(g);
}

void option_https_ranking_https() {
    if (!check_graph_ready()) return;
    https_nodes_sorted_by_https(g);
}

// Option 4: Anomaly detection
void option_anomaly_detection() {
    if (!check_graph_ready()) return;

    printf("\n========== Anomaly Detection: Suspicious Port Scan Nodes ==========\n");
    printf("(Detection: >80%% outbound traffic ratio)\n\n");
    detect_anomaly_nodes(g, 0.8);
}

// Option 5: Path search and congestion analysis
void option_path_analysis() {
    if (!check_graph_ready()) return;

    char src_ip[50], dst_ip[50];

    printf("\n========== Path Search & Congestion Analysis ==========\n");
    printf("Enter source IP address: ");
    scanf("%s", src_ip);
    printf("Enter destination IP address: ");
    scanf("%s", dst_ip);

    // Check if nodes exist
    Node* src = find_node(g, src_ip);
    Node* dst = find_node(g, dst_ip);

    if (src == NULL) {
        printf("\n[Error] Source IP %s not found in graph!\n", src_ip);
        return;
    }
    if (dst == NULL) {
        printf("\n[Error] Destination IP %s not found in graph!\n", dst_ip);
        return;
    }

    printf("\n--- BFS Shortest Path ---\n");
    find_path_bfs(g, src_ip, dst_ip);

    printf("\n--- Dijkstra Minimum Congestion Path ---\n");
    find_path_dijkstra(g, src_ip, dst_ip);
}

// Option 7: ACL check
void option_acl_check() {
    if (!check_graph_ready()) return;
    char target_ip[50], start_ip[50], end_ip[50], rule_type[10];
    printf("\n========== ACL Check ==========\n");
    printf("Enter Target IP: ");
    scanf("%s", target_ip);
    printf("Enter Start IP (range): ");
    scanf("%s", start_ip);
    printf("Enter End IP (range): ");
    scanf("%s", end_ip);
    printf("Enter rule type (Allow/Deny): ");
    scanf("%s", rule_type);
    int is_allow = (strcmp(rule_type, "Allow") == 0 || strcmp(rule_type, "allow") == 0);
    check_acl(g, target_ip, start_ip, end_ip, is_allow);
}

// Main function
int main() {
    // Disable output buffering for proper pipe communication
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    int choice;

    printf("Welcome to the Network Traffic Analysis & Anomaly Detection System!\n");
    printf("This system analyzes network topology and detects abnormal traffic using graph algorithms.\n");
    fflush(stdout);

    while (1) {
        print_menu();

        if (scanf("%d", &choice) != 1) {
            // Clear input buffer
            while (getchar() != '\n');
            printf("\n[Error] Invalid input, please enter a number!\n");
            fflush(stdout);
            continue;
        }

        // Clear newline character from input buffer
        while (getchar() != '\n');

        switch (choice) {
            case 1:
                option_load_data();
                fflush(stdout);
                break;

            case 2:
                option_traffic_ranking();
                fflush(stdout);
                break;

            case 3:
                option_https_ranking();
                fflush(stdout);
                break;

            case 4:
                option_anomaly_detection();
                fflush(stdout);
                break;

            case 5:
                option_path_analysis();
                fflush(stdout);
                break;

            case 6:
                if (!check_graph_ready()) break;
                printf("\n========== Star Structure Detection ==========\n");
                find_star_structures(g);
                fflush(stdout);
                break;

            case 7:
                option_acl_check();
                fflush(stdout);
                break;
            case 8:
                option_load_data_custom();
                fflush(stdout);
                break;
            case 9:
                option_https_ranking_total();
                fflush(stdout);
                break;
            case 10:
                option_https_ranking_https();
                fflush(stdout);
                break;

            case 11:
                if (!check_graph_ready()) break;
                printf("\n========== Filter Nodes with >80%% Unidirectional Traffic ==========\n");
                filter_suspicious_nodes(g, 100);
                fflush(stdout);
                break;

            case 0:
                printf("\nExiting system...\n");
                if (g != NULL) {
                    printf("Releasing graph memory...\n");
                    destroy_graph(g);
                }
                printf("Thank you for using! Goodbye!\n");
                fflush(stdout);
                return 0;

            default:
                printf("\n[Error] Invalid option, please enter a number between 0-7!\n");
                fflush(stdout);
        }
    }

    return 0;
}
