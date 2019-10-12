#!/usr/bin/env python3

tag_description = 'game_match'
region_name = 'eu-central-1'
vpc_cidr = '192.168.8.0/24'

whitelist_ipv4 = '1.2.3.4/32'
whitelist_ipv6 = '1abc:2abc:3abc:4abc:5abc:6abc:7abc:8abc/128'

import boto3, urllib3, uuid, sys, argparse, cryptography, warnings, time
from botocore.config import Config

argparser = argparse.ArgumentParser(prog=sys.argv[0], description='On demand VPN in the cloud')
argparser.add_argument('--proxy', type=str, default=None, required=False, help='configures HTTPS proxy to use, e.g. https://127.0.0.1:8080 or None')
argparser.add_argument('--validate', type=bool, default=True, required=False, help='validate server certificate')
argparser.add_argument('--cleanup_id', type=str, default=None, required=False, help='perform cleanup for the given ID')
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
    config = Config(region_name=region_name)
    print('Not using HTTPS proxy.')
else:
    config = Config(region_name=region_name, proxies = {'https': args.proxy})
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
        vpc = ec2.create_vpc(CidrBlock=vpc_cidr, AmazonProvidedIpv6CidrBlock=True)
        vpc.create_tags(Tags=[
            {'Key': 'Name', 'Value': 'VPC_' + tag_description},
            {'Key': 'CleanupId', 'Value': cleanup_id}])
        vpc.wait_until_available()
        print('Created VPC:', vpc.id)

        ig = ec2.create_internet_gateway()
        ig.attach_to_vpc(VpcId=vpc.id)
        ig.create_tags(Tags=[
            {'Key': 'Name', 'Value': 'IGW_' + tag_description},
            {'Key': 'CleanupId', 'Value': cleanup_id}])
        print('Created Internet Gateway:', ig.id)

        rt = ec2.create_route_table(VpcId=vpc.id)
        rt.create_route(DestinationCidrBlock='0.0.0.0/0', GatewayId=ig.id)
        rt.create_route(DestinationIpv6CidrBlock='::/0', GatewayId=ig.id)
        rt.create_tags(Tags=[
            {'Key': 'Name', 'Value': 'RT_' + tag_description},
            {'Key': 'CleanupId', 'Value': cleanup_id}])
        print('Created route table:', rt.id)

        sn = ec2.create_subnet(
            CidrBlock=vpc_cidr,
            Ipv6CidrBlock=(vpc.ipv6_cidr_block_association_set[0]['Ipv6CidrBlock'])[:-2] + '64',
            VpcId=vpc.id)
        sn.create_tags(Tags=[
            {'Key': 'Name', 'Value': 'SN_' + tag_description},
            {'Key': 'CleanupId', 'Value': cleanup_id}])
        print('Created subnet:', sn.id)
        rt.associate_with_subnet(SubnetId=sn.id)

        sg = ec2.create_security_group(GroupName='SG_' + tag_description, Description='Allowed traffic (in)', VpcId=vpc.id)
        sg.create_tags(Tags=[
            {'Key': 'Name', 'Value': 'SG_' + tag_description},
            {'Key': 'CleanupId', 'Value': cleanup_id}])
        sg.authorize_ingress(IpProtocol='tcp', FromPort=22, ToPort=22, CidrIp=whitelist_ipv4)
        sg.authorize_ingress(IpPermissions=[{
            'IpProtocol': 'tcp',
            'FromPort': 22,
            'ToPort': 22,
            'Ipv6Ranges': [{'CidrIpv6': whitelist_ipv6}]
        }])
        print('Created security group:', sg.id)

        keyname = 'K_' + tag_description + '_' + cleanup_id
        key = ec2.create_key_pair(KeyName=keyname)
        print('Created SSH PEM key:', keyname)
        with open(keyname, 'w') as keyfile:
            keyfile.write(str(key.key_material))

        # Ubuntu Server 18.04 LTS (HVM), SSD Volume Type - ami-0cc0a36f626a4fdf5 (64-bit x86)
        print('Creating instance...')
        instances = ec2.create_instances(ImageId='ami-0cc0a36f626a4fdf5',
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
            {'Key': 'Name', 'Value': 'vpn_' + tag_description},
            {'Key': 'CleanupId', 'Value': cleanup_id}])
        instances[0].wait_until_running()
        print('Instance ' + 'vpn_' + tag_description + ' created and running: ' + instances[0].id)
    else:
        filters = [{'Name': 'tag:CleanupId', 'Values': [cleanup_id]}]

        instances = []
        for instance in list(ec2.instances.filter(Filters=filters)):
            instances.append(instance.id)
            print('Instance to terminate:', instance.id, '(', instance.platform, ',', instance.image.id, ',', instance.state, ')')

        sgs = []
        for sg in list(ec2.security_groups.filter(Filters=filters)):
            sgs.append(sg.id)
            print('Security group to delete:', sg.id, '(', sg.group_name, ')')

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
            print('Internet gateway to delete:', ig.id)
        
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
                    print('Detaching internet gateway:', ig.id, 'from VPC:', vpc)
                    ec2c.detach_internet_gateway(InternetGatewayId=ig.id, VpcId=vpc)
            
            for ig in igs:
                print('Deleting internet gateway:', ig)
                ec2c.delete_internet_gateway(InternetGatewayId=ig)

            for sg in sgs:
                print('Deleting security group', sg)
                ec2c.delete_security_group(GroupId=sg)

            for vpc in vpcs:
                print('Deleting VPC:', vpc)
                ec2c.delete_vpc(VpcId=vpc)
        else:
            print('No cleanup operation performed.')

except:
    extype, exvalue, extrace = sys.exc_info()
    print('An error has occured: %s %s %s' % (extype, exvalue, extrace))
