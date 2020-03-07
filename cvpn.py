#!/usr/bin/env python3

vpc_cidr = '192.168.8.0/24'

import boto3, urllib3, uuid, sys, argparse, warnings, time, socket, paramiko, ipaddress, os
from botocore.config import Config

def ipv4cidr(string):
    try:
        ipv4net = ipaddress.IPv4Network(string)
    except:
        raise argparse.ArgumentTypeError("%r is not a valid IPv4 network" % string)
    return ipv4net

def ipv6cidr(string):
    try:
        ipv6net = ipaddress.IPv6Network(string)
    except:
        raise argparse.ArgumentTypeError("%r is not a valid IPv6 network" % string)
    return ipv6net

def awsregion(string):
    if string not in [
            'us-east-2', # US East (Ohio)
            'us-east-1', # US East (N. Virginia)
            'us-west-1', # US West (N. California)
            'us-west-2', # US West (Oregon)
            'ap-east-1', # Asia Pacific (Hong Kong)
            'ap-south-1', # Asia Pacific (Mumbai)
            'ap-northeast-3', # Asia Pacific (Osaka-Local)
            'ap-northeast-2', # Asia Pacific (Seoul)
            'ap-southeast-1', # Asia Pacific (Singapore)
            'ap-southeast-2', # Asia Pacific (Sydney)
            'ap-northeast-1', # Asia Pacific (Tokyo)
            'ca-central-1', # Canada (Central)
            'eu-central-1', # Europe (Frankfurt)
            'eu-west-1', # Europe (Ireland)
            'eu-west-2', # Europe (London)
            'eu-west-3', # Europe (Paris)
            'eu-north-1', # Europe (Stockholm)
            'me-south-1', # Middle East (Bahrain)
            'sa-east-1']: # South America (São Paulo)
        raise argparse.ArgumentTypeError("%r is not a valid AWS region" % string)
    return string

argparser = argparse.ArgumentParser(prog=sys.argv[0], description='On demand VPN in the cloud')
argparser.add_argument('--proxy', type=str, default=None, required=False, help='configures HTTPS proxy to use, e.g. https://127.0.0.1:8080 or None')
argparser.add_argument('--validate', type=bool, default=True, required=False, help='validate server certificate')
argparser.add_argument('--cleanup_id', type=str, default=None, required=False, help='perform cleanup for the given ID')
argparser.add_argument('--region_name', type=awsregion, default='eu-central-1', required=False, help='region name')
argparser.add_argument('--tag_description', type=str, default='game_match', required=False, help='description to use in tags')
argparser.add_argument('--whitelist_ipv4', type=ipv4cidr, action='append', default=[], required=False, help='IPv4 addresses to whitelist for access (in CIDR notation)')
argparser.add_argument('--whitelist_ipv6', type=ipv6cidr, action='append', default=[], required=False, help='IPv6 addresses to whitelist for access (in CIDR notation)')
args = argparser.parse_args()

create = False
if args.cleanup_id == None:
    # generated UUID is used to cleanup resources
    cleanup_id = uuid.uuid4().hex
    print('Script is run in create mode.')
    create = True
    print('ID that can be used for cleanup is', cleanup_id)
else:
    print('Script is run in cleanup mode.')
    cleanup_id = args.cleanup_id

if args.proxy == None:
    config = Config(region_name=args.region_name)
    print('Not using HTTPS proxy.')
else:
    config = Config(region_name=args.region_name, proxies = {'https': args.proxy})
    print('Using HTTPS proxy:', args.proxy)

if args.validate == True:
    print('Server certificate will be validated.')
else:
    print('Server certificate will not be validated, and warnings about it are disabled.')
    urllib3.disable_warnings()

ec2 = boto3.resource('ec2', verify=args.validate, config=config)
ec2c = boto3.client('ec2', verify=args.validate, config=config)

try:
    if create == True:
        if len(args.whitelist_ipv4) == 0 and len(args.whitelist_ipv6) == 0:
            print('Cannot setup the instance without any IP address whitelisted. Exiting.')
            exit(1)

        amis = ec2c.describe_images(
                Owners=['379101102735'], # Debian official account
                Filters=[{'Name': 'architecture', 'Values': ['x86_64']}])
        for ami in amis['Images']:
            candidate_ami = (ami['ImageId'], ami['CreationDate'], ami['Name'])
            if 'selected_ami' not in globals():
                selected_ami = candidate_ami
            if candidate_ami[1] > selected_ami[1]:
                selected_ami = candidate_ami
        if 'selected_ami' not in globals():
            print('Could not find the AMI for latest Debian. Exiting.')
            exit(1)
        print('AMI selected for provisioning: ' + selected_ami[0] + ' (' + selected_ami[2] + ')')

        vpc = ec2.create_vpc(CidrBlock=vpc_cidr, AmazonProvidedIpv6CidrBlock=True)
        vpc.create_tags(Tags=[
            {'Key': 'Name', 'Value': 'VPC_' + args.tag_description},
            {'Key': 'CleanupId', 'Value': cleanup_id}])
        vpc.wait_until_available()
        print('Created VPC:', vpc.id)

        ig = ec2.create_internet_gateway()
        ig.attach_to_vpc(VpcId=vpc.id)
        ig.create_tags(Tags=[
            {'Key': 'Name', 'Value': 'IGW_' + args.tag_description},
            {'Key': 'CleanupId', 'Value': cleanup_id}])
        print('Created Internet Gateway:', ig.id)

        rt = ec2.create_route_table(VpcId=vpc.id)
        rt.create_route(DestinationCidrBlock='0.0.0.0/0', GatewayId=ig.id)
        rt.create_route(DestinationIpv6CidrBlock='::/0', GatewayId=ig.id)
        rt.create_tags(Tags=[
            {'Key': 'Name', 'Value': 'RT_' + args.tag_description},
            {'Key': 'CleanupId', 'Value': cleanup_id}])
        print('Created route table:', rt.id)

        sn = ec2.create_subnet(
            CidrBlock=vpc_cidr,
            Ipv6CidrBlock=(vpc.ipv6_cidr_block_association_set[0]['Ipv6CidrBlock'])[:-2] + '64',
            VpcId=vpc.id)
        sn.create_tags(Tags=[
            {'Key': 'Name', 'Value': 'SN_' + args.tag_description},
            {'Key': 'CleanupId', 'Value': cleanup_id}])
        print('Created subnet:', sn.id)
        rt.associate_with_subnet(SubnetId=sn.id)

        sg = ec2.create_security_group(GroupName='SG_' + args.tag_description, Description='Allowed traffic (in)', VpcId=vpc.id)
        sg.create_tags(Tags=[
            {'Key': 'Name', 'Value': 'SG_' + args.tag_description},
            {'Key': 'CleanupId', 'Value': cleanup_id}])
        for ipv4 in args.whitelist_ipv4:
            print('Whitelisting IPv4 address', ipv4)
            sg.authorize_ingress(IpProtocol='tcp', FromPort=22, ToPort=22, CidrIp=str(ipv4))
            sg.authorize_ingress(IpProtocol='udp', FromPort=53, ToPort=53, CidrIp=str(ipv4))
        for ipv6 in args.whitelist_ipv6:
            print('Whitelisting IPv6 address', ipv6)
            sg.authorize_ingress(IpPermissions=[{
                'IpProtocol': 'tcp',
                'FromPort': 22,
                'ToPort': 22,
                'Ipv6Ranges': [{'CidrIpv6': str(ipv6)}]
            }])
            sg.authorize_ingress(IpPermissions=[{
                'IpProtocol': 'udp',
                'FromPort': 53,
                'ToPort': 53,
                'Ipv6Ranges': [{'CidrIpv6': str(ipv6)}]
            }])
        print('Created Security Group:', sg.id)

        keyname = 'K_' + args.tag_description + '_' + cleanup_id
        key = ec2.create_key_pair(KeyName=keyname)
        print('Created SSH PEM key:', keyname)
        with open(keyname, 'w') as keyfile:
            keyfile.write(str(key.key_material))
        os.chmod(keyname, 0o600)

        print('Creating instance...')
        instances = ec2.create_instances(ImageId=selected_ami[0],
            InstanceType='t2.micro',
            MaxCount=1,
            MinCount=1,
            KeyName=keyname,
            NetworkInterfaces=[{
                'SubnetId': sn.id,
                'DeviceIndex': 0,
                'Ipv6AddressCount': 1,
                'AssociatePublicIpAddress': True,
                'Groups': [sg.group_id]
            }])
        instances[0].create_tags(Tags=[
            {'Key': 'Name', 'Value': 'vpn_' + args.tag_description},
            {'Key': 'CleanupId', 'Value': cleanup_id}])
        instances[0].wait_until_running()
        print('Instance ' + 'vpn_' + args.tag_description + ' created and running: ' + instances[0].id)

        public_ip_address = str(instances[0].public_ip_address)
        private_ip_address = str(instances[0].private_ip_address)

        print('Connecting to', public_ip_address, 'on port 22 for SFTP...')
        while True:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((public_ip_address, 22))
                break
            except ConnectionRefusedError:
                print('Connection to the instance refused, retrying in 2 seconds...')
                time.sleep(2)
            except TimeoutError:
                print('Connection to the instance timed out, retrying in 2 seconds...')
                time.sleep(2)
        ssh = paramiko.Transport(sock)
        pkey = paramiko.RSAKey.from_private_key_file(keyname)
        ssh.connect(username='admin', pkey=pkey)
        if ssh.is_authenticated():
            print('SFTP connection established.')
        else:
            print('Could not authenticate with the provided key. Exiting.')
            exit(1)
        sftp = paramiko.SFTPClient.from_transport(ssh)
        sftp.put('setup.sh','setup.sh')
        if sftp:
            sftp.close()
        if ssh:
            ssh.close()

        print('Provisioning complete. Execute setup.sh after logging in with:')
        print('ssh -i ' + keyname + ' admin@' + public_ip_address)
    else:
        filters = [{'Name': 'tag:CleanupId', 'Values': [cleanup_id]}]

        instances = []
        for instance in list(ec2.instances.filter(Filters=filters)):
            instances.append(instance.id)
            print('Instance to terminate:', instance.id, '(', instance.platform, ',', instance.image.id, ',', instance.state, ')')

        sgs = []
        for sg in list(ec2.security_groups.filter(Filters=filters)):
            sgs.append(sg.id)
            print('Security Group to delete:', sg.id, '(', sg.group_name, ')')

        sns = []
        for sn in list(ec2.subnets.filter(Filters=filters)):
            sns.append(sn.id)
            print('Subnet to delete:', sn.id, '(', sn.cidr_block, ')')

        rts = []
        for rt in list(ec2.route_tables.filter(Filters=filters)):
            rts.append(rt.id)
            print('Route table to delete:', rt.id, '(for VPC', rt.vpc_id, ')')

        igs = []
        for ig in list(ec2.internet_gateways.filter(Filters=filters)):
            igs.append(ig.id)
            print('Internet Gateway to delete:', ig.id)
        
        vpcs = []
        for vpc in list(ec2.vpcs.filter(Filters=filters)):
            vpcs.append(vpc.id)
            print('VPC to delete:', vpc.id, '(', vpc.cidr_block, ')')
        
        keys = []
        for key in ec2.key_pairs.all():
            if str(key.key_name).endswith(cleanup_id):
                keys.append(str(key.key_name))
                print('SSH key to delete:', str(key.key_name))

        print('Type "yes" if you are sure you want to delete the mentioned resources.')
        line = sys.stdin.readline()

        if line == "yes\n":
            print('Delete operation confirmed...')
            if len(instances) > 0:
                print('Terminating instances', instances)
                waiter = ec2c.get_waiter('instance_terminated')
                ec2c.terminate_instances(InstanceIds=instances)
                waiter.wait(InstanceIds=instances)

            for key in keys:
                print('Deleting SSH key', key)
                ec2c.delete_key_pair(KeyName=key)

            for sn in sns:
                print('Deleting subnet', sn)
                ec2c.delete_subnet(SubnetId=sn)

            for rt in rts:
                routetable = ec2.RouteTable(rt)
                for rta in routetable.associations:
                    print('Deleting routing table association', rta.id, 'for', rt)
                    rta.delete()
                print('Deleting routing table', rt)
                ec2c.delete_route_table(RouteTableId=rt)

            for vpc in vpcs:
                attached = ec2.internet_gateways.filter(Filters=[
                    {'Name': 'tag:CleanupId', 'Values': [cleanup_id]},
                    {'Name': 'attachment.vpc-id', 'Values': [vpc]}])
                for ig in attached:
                    print('Detaching Internet Gateway:', ig.id, 'from VPC:', vpc)
                    ec2c.detach_internet_gateway(InternetGatewayId=ig.id, VpcId=vpc)
            
            for ig in igs:
                print('Deleting Internet Gateway:', ig)
                ec2c.delete_internet_gateway(InternetGatewayId=ig)

            for sg in sgs:
                print('Deleting Security Group', sg)
                ec2c.delete_security_group(GroupId=sg)

            for vpc in vpcs:
                print('Deleting VPC:', vpc)
                ec2c.delete_vpc(VpcId=vpc)
        else:
            print('No cleanup operation performed.')

except:
    extype, exvalue, extrace = sys.exc_info()
    print('An error has occured: %s %s %s' % (extype, exvalue, extrace))


