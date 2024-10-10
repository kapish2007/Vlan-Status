import csv
import ipaddress
import getpass
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
from collections import defaultdict

# Function to connect to the switch and run commands for multiple VLANs
def run_commands_for_vlans(hostname, vlans, username, password):
    device = {
        'device_type': 'cisco_ios',  # Adjust this based on your device
        'host': hostname,
        'username': username,
        'password': password,
        'port': 22,  # Default SSH port
    }

    try:
        print(f"Connecting to {hostname}...")
        connection = ConnectHandler(**device)
        results = []

        for vlan_id, subnet in vlans:
            # Check VLAN status
            print(f"Checking VLAN {vlan_id} status...")
            vlan_status_command = f"show interface vlan {vlan_id} | include line protocol"
            vlan_status = connection.send_command(vlan_status_command)

            # If the output does not contain 'line protocol' or is empty, assume VLAN doesn't exist
            if not vlan_status or 'line protocol' not in vlan_status.lower():
                print(f"VLAN {vlan_id} does not exist on {hostname}")
                results.append({
                    'VLAN ID': vlan_id,
                    'VLAN Interface UP': 'No VLAN found',
                    'Clients Connected': "N/A"
                })
                continue

            # Check if the VLAN interface is up
            vlan_up = "line protocol is up" in vlan_status.lower()

            # Get ARP table for the specific VLAN
            print(f"Retrieving ARP table for VLAN {vlan_id}...")
            arp_command = f"show ip arp vlan {vlan_id}"
            arp_output = connection.send_command(arp_command)

            # Check for clients connected on the VLAN
            clients_connected = check_clients(arp_output, subnet)

            results.append({
                'VLAN ID': vlan_id,
                'VLAN Interface UP': vlan_up,
                'Clients Connected': clients_connected
            })

        # Disconnect from the device after processing all VLANs
        connection.disconnect()
        return results

    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        print(f"Connection failed: {e}")
        return None  # Indicate failure to connect

# Function to check for clients in the ARP output while ignoring the first three IPs
def check_clients(arp_output, subnet):
    if arp_output is None:
        return False  # If there's no output, we can't have any clients

    net = ipaddress.ip_network(subnet)
    first_three_ips = {str(ip) for ip in list(net.hosts())[:3]}

    clients_connected = False
    for line in arp_output.splitlines():
        if line.strip() == "":
            continue  # Skip empty lines
        parts = line.split()
        if len(parts) >= 3:  # Assuming the output has at least IP and MAC addresses
            ip = parts[1]  # Adjust this index based on actual output format
            if ip not in first_three_ips:
                clients_connected = True
                break

    return clients_connected

# Function to process the CSV and generate the report
def process_csv(input_file, output_file):
    results = []

    username = input("Enter your SSH username: ")
    password = getpass.getpass("Enter your SSH password (special characters are allowed): ")

    # Group VLANs by hostname
    hostname_to_vlans = defaultdict(list)
    with open(input_file, mode='r') as csv_file:
        csv_reader = csv.DictReader(csv_file)
        for row in csv_reader:
            hostname = row['Hostname']
            vlan_id = row['VLAN ID']
            subnet = row['Subnet']
            hostname_to_vlans[hostname].append((vlan_id, subnet))

    # Process each hostname and its associated VLANs
    for hostname, vlans in hostname_to_vlans.items():
        # Run the commands once per device for all VLANs
        vlan_results = run_commands_for_vlans(hostname, vlans, username, password)

        if vlan_results is None:  # Indicates a failure in connecting
            print(f"Skipping {hostname} due to connection issues.")
            continue

        # Append results for each VLAN
        for vlan_result in vlan_results:
            results.append({
                'Hostname': hostname,
                'VLAN ID': vlan_result['VLAN ID'],
                'VLAN Interface UP': vlan_result['VLAN Interface UP'],
                'Clients Connected': vlan_result['Clients Connected']
            })

    write_to_csv(output_file, results)

# Function to write the results to a CSV file
def write_to_csv(output_file, results):
    fieldnames = ['Hostname', 'VLAN ID', 'VLAN Interface UP', 'Clients Connected']

    with open(output_file, mode='w', newline='') as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()

        for result in results:
            writer.writerow(result)

# Main function
if __name__ == '__main__':
    input_file = 'input.csv'   # Input CSV file path
    output_file = 'output.csv'  # Output CSV file path

    process_csv(input_file, output_file)
    print(f"Results written to {output_file}")
