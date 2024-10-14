import csv
import ipaddress
import getpass
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
from collections import defaultdict
from openpyxl import Workbook

# Function to generate VLAN cleanup configurations and save them in an Excel file
# Function to generate VLAN cleanup configurations and save them in an Excel file
def generate_vlan_cleanup_config(source_file, config_file):
    # Initialize a workbook and a worksheet
    wb = Workbook()
    ws = wb.active
    ws.title = "VLAN Cleanup Config"

    # Write headers for the Excel file
    ws.append(["Hostname", "Configuration"])

    with open(source_file, mode='r') as csv_file:
        csv_reader = csv.DictReader(csv_file)
        hostname_dict = defaultdict(list)

        for row in csv_reader:
            hostname = row['Hostname']
            access_ports = row['Access Ports']
            if access_ports != "No access ports found":
                access_ports_list = access_ports.split(', ')  # Split the ports into a list
                # Prepare configuration commands for each access port
                for port in access_ports_list:
                    config_command = f"Default interface {port.strip()}\ninterface {port.strip()}\n  shutdown\n  description SHUTDOWN"
                    hostname_dict[hostname].append(config_command)

    # Write configurations for each hostname
    for hostname, commands in hostname_dict.items():
        ws.append([hostname, "\n".join(commands)])  # Join all commands with a newline

    # Save the Excel file
    wb.save(config_file)
    print(f"VLAN cleanup configuration saved to {config_file}")

# Function to check for VLAN access ports using simplified command
def check_access_ports(connection, vlan_id):
    # Command to filter only the active VLANs and their ports
    vlan_ports_command = f"show vlan id {vlan_id} | i active"
    vlan_ports_output = connection.send_command(vlan_ports_command)

    # Initialize a variable to store the ports
    access_ports = []

    # Split the output into lines
    vlan_ports_lines = vlan_ports_output.splitlines()

    # Iterate over the lines to extract the ports column
    for line in vlan_ports_lines:
        # Split the line into parts by whitespace
        parts = line.split()

        # Ensure the line has at least 4 columns (vlan_id, VLAN name, status, and ports)
        if len(parts) >= 4:
            # Capture everything from the 4th column onward (ports) as a single string
            access_ports.append(' '.join(parts[3:]))

    # Join all ports into a single string if there are multiple lines, else return the single line
    return ', '.join(access_ports) if access_ports else "No access ports found"

    
def check_clients(arp_output, subnet):
    if arp_output is None:
        return False  # If there's no output, assume no clients

    # Split the ARP output into lines
    arp_lines = arp_output.splitlines()

    # Look for the header row (assuming the first non-empty line contains headers)
    header_row = None
    for line in arp_lines:
        if line.strip():  # Skip empty lines
            header_row = line.split()  # Split header into columns
            break

    if header_row is None:
        print("No header found in ARP output.")
        return False

    # Find the index of the "Address" column in the header
    try:
        address_index = header_row.index("Address")
    except ValueError:
        print("No 'Address' column found in ARP output.")
        return False

    # Get the first three IPs in the subnet
    net = ipaddress.ip_network(subnet)
    first_three_ips = {str(ip) for ip in list(net.hosts())[:3]}  # Create a set of the first 3 IPs

    # Flag to track if there are other clients
    clients_connected = False

    # Process each line of the ARP output, starting after the header
    for line in arp_lines[1:]:  # Skip the first line (header)
        if line.strip() == "":  # Skip empty lines
            continue

        parts = line.split()
        if len(parts) > address_index:  # Ensure the line has enough columns
            ip_address = parts[address_index]  # Get the IP address from the Address column

            # Skip rows where 'Address' is repeated (this means we're still reading the header)
            if ip_address == "Address":
                continue
            print(ip_address)
            # If the IP is not one of the first three, we have a client connected
            if ip_address not in first_three_ips:
                clients_connected = True
                break

    return clients_connected


# Function to run commands for a list of VLANs once connected to a switch
def run_commands_for_vlans(connection, vlans):
    results = []

    for vlan_id, subnet in vlans:
        # Check VLAN status
        print(f"Checking VLAN {vlan_id} status...")
        vlan_status_command = f"show interface vlan {vlan_id}"
        vlan_status = connection.send_command(vlan_status_command)  # Add expect_string

        if 'line protocol is up' in vlan_status.lower():
            vlan_up = "line protocol is up" in vlan_status.lower()

            # Get ARP table for the specific VLAN
            print(f"Retrieving ARP table for VLAN {vlan_id}...")
            arp_command = f"show ip arp vlan {vlan_id} | begin Address"
            arp_output = connection.send_command(arp_command)  # Add expect_string
    
            # Check for clients connected on the VLAN
            clients_connected = check_clients(arp_output, subnet)
            print(f"Retrieving access ports for VLAN {vlan_id}...")
            access_ports = check_access_ports(connection, vlan_id)
            print(access_ports)
            results.append({
                'VLAN ID': vlan_id,
                'VLAN Interface UP': vlan_up,
                'Clients Connected': clients_connected,
                'Access Ports': access_ports
            })
            
        elif 'line protocol is down' in vlan_status.lower():
            print(f"VLAN {vlan_id} is down")
            results.append({
                'VLAN ID': vlan_id,
                'VLAN Interface UP': 'DOWN',
                'Clients Connected': "N/A",
                'Access Ports': "N/A"
            })

        else:
            print(f"VLAN {vlan_id} does not exist.")
            results.append({
                'VLAN ID': vlan_id,
                'VLAN Interface UP': 'No VLAN found',
                'Clients Connected': "N/A",
                'Access Ports': "N/A"
            })
            
    return results
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
        # Connect to the switch once per hostname
        device = {
            'device_type': 'cisco_ios',  # Use this for Nexus devices
            'host': hostname,
            'username': username,
            'password': password,
            'port': 22,  # Default SSH port
            'global_delay_factor': 2,  # Adjust this if the device is slow
        }

        try:
            print(f"Connecting to {hostname}...")
            connection = ConnectHandler(**device)

            # Run the commands once per device for all VLANs
            vlan_results = run_commands_for_vlans(connection, vlans)

            # Disconnect after all VLANs are processed
            connection.disconnect()

            # Append results for each VLAN
            for vlan_result in vlan_results:
                results.append({
                    'Hostname': hostname,
                    'VLAN ID': vlan_result['VLAN ID'],
                    'VLAN Interface UP': vlan_result['VLAN Interface UP'],
                    'Clients Connected': vlan_result['Clients Connected'],
                    'Access Ports': vlan_result['Access Ports']
                })

        except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
            print(f"Connection failed for {hostname}: {e}")
            continue  # Skip this hostname if connection fails

    write_to_csv(output_file, results)

# Function to write the results to a CSV file
def write_to_csv(output_file, results):
    fieldnames = ['Hostname', 'VLAN ID', 'VLAN Interface UP', 'Clients Connected', 'Access Ports']

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

    # Ask user if they want to continue to generate configuration
    continue_cleanup = input("Do you want to continue to generate configuration for VLAN cleanup? (yes/no): ").strip().lower()

    if continue_cleanup == 'yes':
        # Generate VLAN cleanup configuration in Excel
        generate_vlan_cleanup_config(output_file, 'vlan_cleanup_config.xlsx')
    else:
        print("Exiting without generating configuration.")

