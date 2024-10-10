import csv
import ipaddress
import getpass
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException

# Function to connect to the switch and run commands
def run_commands(hostname, vlan_id, username, password):
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

        # Check VLAN status
        print(f"Checking VLAN {vlan_id} status...")
        vlan_status_command = f"show interface vlan {vlan_id} | include line protocol"
        vlan_status = connection.send_command(vlan_status_command)

        # If the output does not contain 'line protocol' or is empty, assume VLAN doesn't exist
        if not vlan_status or 'line protocol' not in vlan_status.lower():
            print(f"VLAN {vlan_id} does not exist on {hostname}")
            connection.disconnect()
            return "No VLAN found", None

        # Check if the VLAN interface is up
        vlan_up = "line protocol is up" in vlan_status.lower()

        # Get ARP table for the specific VLAN
        print(f"Retrieving ARP table for VLAN {vlan_id}...")
        arp_command = f"show ip arp vlan {vlan_id}"
        arp_output = connection.send_command(arp_command)

        # Disconnect from the device
        connection.disconnect()

        return vlan_up, arp_output

    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        print(f"Connection failed: {e}")
        return None, None  # Indicate failure to connect

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

    with open(input_file, mode='r') as csv_file:
        csv_reader = csv.DictReader(csv_file)

        for row in csv_reader:
            hostname = row['Hostname']
            vlan_id = row['VLAN ID']
            subnet = row['Subnet']

            # Run the commands once per device
            vlan_up, arp_output = run_commands(hostname, vlan_id, username, password)

            if vlan_up == "No VLAN found":
                print(f"VLAN {vlan_id} does not exist on {hostname}")
                results.append({
                    'Hostname': hostname,
                    'VLAN ID': vlan_id,
                    'VLAN Interface UP': vlan_up,
                    'Clients Connected': "N/A"  # No clients since VLAN doesn't exist
                })
                continue

            if vlan_up is None:  # Indicates a failure in connecting
                print(f"Skipping {hostname} due to connection issues.")
                continue

            # Check for clients connected on the VLAN
            clients_connected = check_clients(arp_output, subnet)

            results.append({
                'Hostname': hostname,
                'VLAN ID': vlan_id,
                'VLAN Interface UP': vlan_up,
                'Clients Connected': clients_connected
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
