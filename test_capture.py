"""
Test script to verify capture and load functionality
"""
import csv

# Create a test captured.csv file
test_data = [
    ["Source", "Destination", "Protocol", "SrcPort", "DstPort", "DataSize", "Duration"],
    ["192.168.1.100", "8.8.8.8", "6", "54321", "443", "1500", "120.500"],
    ["192.168.1.100", "1.1.1.1", "17", "12345", "53", "512", "50.250"],
    ["10.0.0.1", "192.168.1.100", "6", "80", "54322", "2048", "200.750"],
]

with open("test_captured.csv", "w", encoding="utf-8", newline='') as f:
    writer = csv.writer(f)
    writer.writerows(test_data)

print("Created test_captured.csv with 3 flows")
print("\nContent:")
with open("test_captured.csv", "r") as f:
    print(f.read())
