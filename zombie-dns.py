import boto3
from botocore.exceptions import ClientError
import ipaddress

# Initialize AWS clients
route53 = boto3.client('route53')
ec2 = boto3.client('ec2')

def list_hosted_zones():
    """List all Route 53 hosted zones and their IDs."""
    try:
        paginator = route53.get_paginator('list_hosted_zones')
        hosted_zones = []
        for page in paginator.paginate():
            hosted_zones.extend(page['HostedZones'])
        return hosted_zones
    except ClientError as e:
        print(f"Error listing hosted zones: {e}")
        return []

def list_dns_records(hosted_zone_id):
    """List all DNS records for a given hosted zone."""
    try:
        paginator = route53.get_paginator('list_resource_record_sets')
        record_sets = []
        for page in paginator.paginate(HostedZoneId=hosted_zone_id):
            record_sets.extend(page['ResourceRecordSets'])
        return record_sets
    except ClientError as e:
        print(f"Error listing DNS records for zone {hosted_zone_id}: {e}")
        return []

def extract_ip_records(record_sets):
    """Extract IP addresses from DNS records and map them to their records."""
    ip_records = {}
    for record in record_sets:
        if record['Type'] == 'A':
            for r in record['ResourceRecords']:
                ip = r['Value']
                if ip not in ip_records:
                    ip_records[ip] = []
                ip_records[ip].append(record)
    return ip_records

def get_current_elastic_ips():
    """Get the current Elastic IPs allocated to the account."""
    try:
        response = ec2.describe_addresses()
        return set(address['PublicIp'] for address in response['Addresses'])
    except ClientError as e:
        print(f"Error retrieving Elastic IPs: {e}")
        return set()

def find_unused_ips(ip_records, current_ips):
    """Find IPs in DNS records that are no longer controlled by the account."""
    unused_ips = {}
    for ip, records in ip_records.items():
        if ip not in current_ips:
            unused_ips[ip] = records
    return unused_ips

def is_private_ip(ip):
    """Check if an IP address is a private IP address."""
    try:
        ip_addr = ipaddress.ip_address(ip)
        return ip_addr.is_private
    except ValueError:
        return False

def main():
    # Get all hosted zones
    print("Listing hosted zones...")
    hosted_zones = list_hosted_zones()
    
    if not hosted_zones:
        print("No hosted zones found.")
        return
    
    # Get current Elastic IPs
    print("Getting current Elastic IPs...")
    current_ips = get_current_elastic_ips()
    
    if not current_ips:
        print("No Elastic IPs found.")
        return
    
    # Process each hosted zone
    for zone in hosted_zones:
        hosted_zone_id = zone['Id']
        print(f"\nProcessing Hosted Zone: {zone['Name']} (ID: {hosted_zone_id})")
        
        # List DNS records
        print("Listing DNS records...")
        record_sets = list_dns_records(hosted_zone_id)
        
        # Extract IP addresses and their records
        print("Extracting IP addresses and mapping records...")
        ip_records = extract_ip_records(record_sets)
        
        # Find unused IPs and associated records
        print("Finding unused IPs...")
        unused_ips = find_unused_ips(ip_records, current_ips)
        
        # Output results
        if unused_ips:
            print("Unused Elastic IPs found in this zone:")
            for ip, records in unused_ips.items():
                ip_type = "Private" if is_private_ip(ip) else "Public"
                print(f"  IP: {ip} ({ip_type})")
                for record in records:
                    print(f"    Record Name: {record['Name']}, Type: {record['Type']}")
        else:
            print("No unused Elastic IPs found in this zone.")

if __name__ == "__main__":
    main()
