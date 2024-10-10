import csv
import paramiko
import ipaddress
import getpass

# Function to SSH into the device and run multiple commands in a single session
def ssh_run_commands(hostname, commands, username, password):
    results = {}
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname, username=username, password=password, allow_agent=False, look_for_keys=False)

        # Open a new SSH session and run each command
        for command_label, command in commands.items():
            stdin, stdout, stderr = ssh.exec_command(command)
            output = stdout.read().decode()
            results[command_label] = output
            
        ssh.close()
    except paramiko.SSHException as e:
        print(f"SSHException: {e}")
        return None
    except Exception as e:
        print(f"Error: {e}")
        return None

    return results

# Function to check if the VLAN interface is UP based on the output
def is_vlan_up(output):
    return 'line protocol is up' in output.lower()

# Function to check if there are any ARP/MAC addresses (clients) on the VLAN while ignoring the first three IPs
def check_arp_mac(output, subnet):
    net = ipaddress.ip_network(subnet)
    first_three_ips = {str(ip) for ip in list(net.hosts())[:3]}

    arp_entries = [line.split()[1] for line in output.splitlines() if len(line.split()) > 1]

    for ip in arp_entries:
        if ip not in first_three_ips:
            return True  # Clients are connected

    return False  # No clients other than the first 3 management IPs

# Function to process CSV and generate the report
def process_csv(input_file, output_file, username, password):
    results = []

    with open(input_file, mode='r') as csv_file:
        csv_reader = csv.DictReader(csv_file)

        for row in csv_reader:
            hostname = row['Hostname']
            vlan_id = row['VLAN ID']
            subnet = row['Subnet']

            # Define the commands to be run in a single SSH session
            commands = {
                'vlan_status': f"show interface vlan {vlan_id} | i up",
                'arp_table': f"show ip arp vlan {vlan_id}"
            }

            # Run the commands once per device
            command_outputs = ssh_run_commands(hostname, commands, username, password)

            if not command_outputs:
                print(f"Skipping {hostname} due to connection issues.")
                continue

            vlan_up = is_vlan_up(command_outputs['vlan_status'])
            clients_connected = check_arp_mac(command_outputs['arp_table'], subnet)

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
    output_file = 'output.csv' # Output CSV file path

    username = input("Enter your SSH username: ")
    password = getpass.getpass("Enter your SSH password: ")

    process_csv(input_file, output_file, username, password)
    print(f"Results written to {output_file}")
