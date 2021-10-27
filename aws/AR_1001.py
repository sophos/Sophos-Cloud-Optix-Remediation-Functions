"""
Copyright 2021 Sophos Ltd. All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License");
You may not use this file except in compliance with the License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0. Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied. See the License for the specific language governing permissions and limitations
#under the License.
"""

"""
    Rule remediation
        AR-1001 -> Flag resource(s) with public IP and Security Group with ingress from any source on any port.
"""

import boto3

IPV4_HOLDER = '0.0.0.0/0'
IPV6_HOLDER = '::/0'

rule = 'AR-1001'
# should not delete the whole security group but rather just modify the unwanted rule.
want_to_delete_the_whole_security_group = False


def rds_sec_group_allowed(sec_group_rules, rds_port):
    """ Open Security Group rules.

        Args:
            sec_group_rules (dict):
                All the Security group rules for rds
            rds_port (int):
                RDS running port

        Returns:
            bool: If Open IPV4 or IPv6 and Security group ports are matching.
    """
    if sec_group_rules.get('SecurityGroupRules'):
        for sec_group_rule in sec_group_rules['SecurityGroupRules']:
            if (sec_group_rule.get('CidrIpv4')
                and sec_group_rule['CidrIpv4'] == IPV4_HOLDER) or (
                    sec_group_rule.get('CidrIpv6')
                    and sec_group_rule['CidrIpv6'] == IPV6_HOLDER):
                if sec_group_rule['FromPort'] == sec_group_rule['ToPort'] or (
                        sec_group_rule['FromPort'] <= rds_port <= sec_group_rule['ToPort']):
                    return True
    return False


def vpc_security_group_list(rds_instance):
    """ If VPC security group rule is open to public add to List and return.

        Args:
            rds_instance (dict):
                All the running rds instance on the region

        Returns:
            list: List of VPC Security Group Id's
    """
    vpc_list = []
    if rds_instance.get('VpcSecurityGroups'):
        for sec_group in rds_instance['VpcSecurityGroups']:
            if sec_group['Status'] == 'active':
                sec_group_rule = ec2.describe_security_group_rules(Filters=[
                    {
                        'Name': 'group-id',
                        'Values': [
                            sec_group['VpcSecurityGroupId']
                        ]
                    },
                ], MaxResults=512)
                if rds_sec_group_allowed(sec_group_rule, rds_instance['DbInstancePort']):
                    vpc_list.append(sec_group['VpcSecurityGroupId'])
    return vpc_list


def db_sec_group_list(rds_instance):
    db_list = []
    if rds_instance.get('DBSecurityGroups'):
        for sec_group in rds_instance['DBSecurityGroups']:
            security_groups = rds.describe_db_security_groups(
                DBSecurityGroupName=sec_group['DBSecurityGroupName'])
            if security_groups.get('DBSecurityGroups'):
                for security_group in security_groups['DBSecurityGroups']:
                    if security_group.get('EC2SecurityGroups'):
                        if security_group['EC2SecurityGroups']['Status'] == 'active':
                            sec_group_rule = ec2.describe_security_group_rules(Filters=[
                                {
                                    'Name': 'group-id',
                                    'Values': [
                                        security_group['EC2SecurityGroups']['EC2SecurityGroupId']
                                    ]
                                },
                            ], MaxResults=512)
                            if rds_sec_group_allowed(sec_group_rule, rds_instance['DbInstancePort']):
                                db_list.append(security_group['EC2SecurityGroups']['EC2SecurityGroupId'])
    return db_list


def is_cid_rip(rds_instance):
    if rds_instance.get('DBSecurityGroups'):
        for sec_group in rds_instance['DBSecurityGroups']:
            security_groups = rds.describe_db_security_groups(
                DBSecurityGroupName=sec_group['DBSecurityGroupName'])
            if security_groups.get('DBSecurityGroups'):
                for security_group in security_groups['DBSecurityGroups']:
                    if security_group.get('IPRanges'):
                        for ip_ranges in security_group['IPRanges']:
                            if ip_ranges.get('CIDRIP'):
                                if IPV4_HOLDER in ip_ranges['CIDRIP'] or IPV6_HOLDER in ip_ranges['CIDRIP']:
                                    return False
    return True


def is_true(rds_instance):
    if not rds_instance['PubliclyAccessible']:
        return False
    is_vpc_sec_group = True
    is_ec2_classic_sec_group = True
    vpc_list = vpc_security_group_list(rds_instance)
    if vpc_list:
        is_vpc_sec_group = len(vpc_list) == 0
    db_list = db_sec_group_list(rds_instance)
    if db_list:
        is_ec2_classic_sec_group = len(db_list) == 0
    is_cid_rip_range = is_cid_rip(rds_instance)
    return not is_vpc_sec_group or not is_ec2_classic_sec_group or not is_cid_rip_range


def is_network_interface_public(network_interfaces):
    is_public = False
    if network_interfaces:
        for network_interface in network_interfaces:
            if network_interface.get('Association'):
                if network_interface['Association']['PublicIp'] != "":
                    is_public = True
                    break
    return is_public


def rectify_open_sec_group_assigned(sec_group_rules, group_id):
    if sec_group_rules.get('SecurityGroupRules'):
        for sec_group_rule in sec_group_rules['SecurityGroupRules']:
            if sec_group_rule.get('IpProtocol') and sec_group_rule['IpProtocol'].upper() != 'ICMP':
                if (sec_group_rule.get('CidrIpv4')
                    and sec_group_rule['CidrIpv4'] == IPV4_HOLDER) or (
                        sec_group_rule.get('CidrIpv6')
                        and sec_group_rule['CidrIpv6'] == IPV6_HOLDER):
                    if sec_group_rule['FromPort'] == -1 or (
                            sec_group_rule['FromPort'] == 0 and sec_group_rule['ToPort'] == 65535):
                        modify_or_delete(group_id, sec_group_rule['SecurityGroupRuleId'])


def modify_or_delete(group_id, sec_group_rule_id):
    if want_to_delete_the_whole_security_group:
        ec2.delete_security_group(GroupId=group_id)
    else:
        modify_security_group_rules(group_id, sec_group_rule_id)


def modify_security_group_rules(group_id, sec_group_rule_id):
    response = None
    try:
        response = ec2.revoke_security_group_ingress(
            GroupId=group_id,
            SecurityGroupRuleIds=[sec_group_rule_id]
        )
    except Exception as e:
        print(e)
    if not response:
        try:
            response = ec2.revoke_security_group_egress(
                GroupId=group_id,
                SecurityGroupRuleIds=[sec_group_rule_id]
            )
        except Exception as e:
            print(e)
    print("Response from revoke security group: " + str(response))


def check_and_rectify_db_sec_group(db_security_groups):
    if db_security_groups:
        for db_security_group in db_security_groups:
            security_groups = rds.describe_db_security_groups(
                DBSecurityGroupName=db_security_group['DBSecurityGroupName'])
            if security_groups.get('DBSecurityGroups'):
                for security_group in security_groups['DBSecurityGroups']:
                    if security_group.get('EC2SecurityGroups'):
                        check_and_rectify_rds_security_group(security_group.get('EC2SecurityGroups'),
                                                             'EC2SecurityGroupId')


def check_and_rectify_rds_security_group(rds_security_groups, group_id_var):
    if rds_security_groups:
        for rds_security_group in rds_security_groups:
            sec_group_rules = ec2.describe_security_group_rules(Filters=[
                {
                    'Name': 'group-id',
                    'Values': [
                        rds_security_group[group_id_var]
                    ]
                },
            ], MaxResults=512)
            rectify_open_sec_group_assigned(sec_group_rules, rds_security_group[group_id_var])


def check_and_rectify_elb_security_group(security_groups):
    if security_groups:
        for security_group in security_groups:
            sec_group_rules = ec2.describe_security_group_rules(Filters=[
                {
                    'Name': 'group-id',
                    'Values': [
                        security_group
                    ]
                },
            ], MaxResults=512)
            rectify_open_sec_group_assigned(sec_group_rules, security_group)


def check_and_rectify_es_security_group(security_group_ids):
    if security_group_ids:
        for security_group_id in security_group_ids:
            sec_group_rules = ec2.describe_security_group_rules(Filters=[
                {
                    'Name': 'group-id',
                    'Values': [
                        security_group_id
                    ]
                },
            ], MaxResults=512)
            rectify_open_sec_group_assigned(sec_group_rules, security_group_id)


def lambda_handler(event, context, ec2_regions):
    """ This single rule can be caused at 4 different resources, namely
        EC2, RDS, ELB and ES...

        Args:
            event (dict):
                This is the payload with is sent via Optix, whenever an alert is generated.
            context (dict):
                This is the AWS lambda context.
            ec2_regions (list):
                List of all available regions

        Returns:
            str: Always returns "Remediation successful". Everything else is logged.
    """
    payload_data = event['payloadData']
    rule_id = payload_data['ruleNumber']
    if event['eventType'] == 'ALERT' and rule_id == rule:
        affected_resources = payload_data['affectedResources']
        for reg in ec2_regions:
            global ec2
            ec2 = boto3.client('ec2', region_name=reg)
            global rds
            rds = boto3.client('rds', region_name=reg)
            global elb_v2
            elb_v2 = boto3.client('elbv2', region_name=reg)
            global es
            es = boto3.client('es', region_name=reg)
            for affected_resource in affected_resources:
                if affected_resource['state'] == "OPEN":
                    try:
                        # EC2 instance alert check
                        ec2_instances = ec2.describe_instances()
                        if ec2_instances and ec2_instances.get('Reservations'):
                            for reservation in ec2_instances['Reservations']:
                                if reservation.get('Instances'):
                                    for instance in reservation['Instances']:
                                        if instance['InstanceId'] in affected_resource['resourceInfo']:
                                            is_public = is_network_interface_public(instance.get('NetworkInterfaces'))
                                            if instance.get('SecurityGroups'):
                                                for security_group in instance['SecurityGroups']:
                                                    sec_group_rules = ec2.describe_security_group_rules(Filters=[
                                                        {
                                                            'Name': 'group-id',
                                                            'Values': [
                                                                security_group['GroupId']
                                                            ]
                                                        },
                                                    ], MaxResults=512)
                                                    if is_public:
                                                        rectify_open_sec_group_assigned(sec_group_rules,
                                                                                        security_group['GroupId'])
                        # rds instance alert check
                        db_instances = rds.describe_db_instances()
                        if db_instances and db_instances.get('DBInstances'):
                            for db_instance in db_instances['DBInstances']:
                                if db_instance['DBInstanceIdentifier'] in affected_resource['resourceInfo']:
                                    if is_true(db_instance):
                                        check_and_rectify_db_sec_group(db_instance.get('DBSecurityGroups'))
                                        check_and_rectify_rds_security_group(db_instance.get('VpcSecurityGroups'),
                                                                             'VpcSecurityGroupId')
                        # load balancer instance alert check
                        load_balancers = elb_v2.describe_load_balancers()
                        if load_balancers and load_balancers.get('LoadBalancers'):
                            for load_balancer in load_balancers['LoadBalancers']:
                                if load_balancer.get('SecurityGroups') and load_balancer['Scheme'] == 'internet-facing':
                                    if load_balancer['DNSName'] in affected_resource['resourceInfo']:
                                        check_and_rectify_elb_security_group(load_balancer.get('SecurityGroups'))
                        # Elastic search instance alert check
                        es_domain_names = es.list_domain_names()
                        if es_domain_names and es_domain_names.get('DomainNames'):
                            for es_domain_name in es_domain_names['DomainNames']:
                                if es_domain_name['DomainName'] in affected_resource['resourceInfo']:
                                    es_domain_config = es.describe_elasticsearch_domain_config(
                                        DomainName=es_domain_name['DomainName'])
                                    if es_domain_config:
                                        es_vpc_options = es_domain_config['DomainConfig']['VPCOptions']
                                        if es_vpc_options:
                                            security_group_ids = es_vpc_options['Options']['SecurityGroupIds']
                                            check_and_rectify_es_security_group(security_group_ids)
                    except Exception as e:
                        print(e)
        return "Remediation Successful"
