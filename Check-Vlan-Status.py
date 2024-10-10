import paramiko
import ipaddress
import csv
import time

def ssh_connect(hostname, username, password):
    """Connects to the device via SSH and returns the SSH client."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname, username=username, password=password, look_for_keys=False)
        return client
    except Exception as e:
        print(f"Failed to connect to {hostname}: {e}")
        return None

def execute_command(client, command):
    """Executes a command on the SSH client and returns the output."""
    stdin, stdout, stderr = client.exec_command(command)
    output = stdout.read().decode()
    return output

def check_vlan_status_and_clients(command_outputs, vlan_id, subnet):
    vlan_status = command_outputs.get('vlan_status')

    if not vlan_status:
        print(f"VLAN {vlan_id} not found.")
        results.append({
            'VLAN ID': vlan_id,
            'VLAN Interface UP': 'No VLAN found',
            'Clients Connected': "N/A"
        })
        return

    if 'line protocol is down' in vlan_status.lower():
        print(f"VLAN {vlan_id} is DOWN.")
        results.append({
            'VLAN ID': vlan_id,
            'VLAN Interface UP': 'DOWN',
            'Clients Connected': "N/A"
        })
        return

    if 'line protocol is up' in vlan_status.lower():
        print(f"VLAN {vlan_id} is UP.")
        
        arp_output = command_outputs.get('arp_output')
        if arp_output is None:
            print(f"No ARP output found for VLAN {vlan_id}.")
            results.append({
                'VLAN ID': vlan_id,
                'VLAN Interface UP': 'UP',
                'Clients Connected': "N/A"
            })
            return

        try:
            clients_connected = check_clients(arp_output, subnet)
            results.append({
                'VLAN ID': vlan_id,
                'VLAN Interface UP': 'UP',
                'Clients Connected': "Yes" if clients_connected else "No"
            })
        except Exception as e:
            print(f"Error checking clients for VLAN {vlan_id}: {e}")
            results.append({
                'VLAN ID': vlan_id,
                'VLAN Interface UP': 'UP',
                'Clients Connected': "Error"
            })

def check_clients(arp_output, subnet):
    """Checks if there are clients connected to the specified VLAN."""
    if arp_output is None:
        return False

    arp_lines = arp_output.splitlines()
    header_row = None
    for line in arp_lines:
        if line.strip():
            header_row = line.split()
            break

    if header_row is None:
        print("No header found in ARP output.")
        return False

    try:
        address_index = header_row.index("Address")
    except ValueError:
        print("No 'Address' column found in ARP output.")
        return False

    net = ipaddress.ip_network(subnet)
    first_three_ips = {str(ip) for ip in list(net.hosts())[:3]}
    clients_connected = False

    for line in arp_lines[1:]:
        if line.strip() == "":
            continue

        parts = line.split()
        if len(parts) > address_index:
            ip_address = parts[address_index]

            if ip_address == "Address":
                continue

            if ip_address not in first_three_ips:
                clients_connected = True
                break

    return clients_connected

def main():
    input_file = 'input.csv'  # Input CSV file
    output_file = 'output.csv'  # Output CSV file
    global results
    results = []

    # User credentials
    username = input("Enter SSH username: ")
    password = input("Enter SSH password: ")

    with open(input_file, 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        hosts = {}

        for row in reader:
            hostname = row['Hostname']
            vlan_id = row['VLAN ID']
            subnet = row['Subnet']

            if hostname not in hosts:
                hosts[hostname] = []
            hosts[hostname].append((vlan_id, subnet))

    for hostname, vlan_data in hosts.items():
        client = ssh_connect(hostname, username, password)

        if client:
            time.sleep(1)  # Small delay for connection stability
            for vlan_id, subnet in vlan_data:
                # Commands to execute
                vlan_command = f"show interface vlan {vlan_id} | include line protocol"
                arp_command = f"show ip arp vlan {vlan_id}"

                # Execute commands
                vlan_status = execute_command(client, vlan_command)
                arp_output = execute_command(client, arp_command)

                command_outputs = {
                    'vlan_status': vlan_status,
                    'arp_output': arp_output
                }

                check_vlan_status_and_clients(command_outputs, vlan_id, subnet)

            client.close()
        else:
            print(f"Skipping hostname {hostname} due to connection issues.")

    # Write results to CSV
    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = ['VLAN ID', 'VLAN Interface UP', 'Clients Connected']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        writer.writerows(results)

    print(f"Results written to {output_file}")

if __name__ == "__main__":
    main()
