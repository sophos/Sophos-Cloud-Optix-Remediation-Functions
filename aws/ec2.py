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
    ec2 current Rule remediation by this function.
        AR-309 -> Accidentally Publicly shared AMIs.
        AR-651 -> Ensure no security groups allow ingress from 0.0.0.0/0 to port 22.
        AR-1044 -> Flag security-groups which are attached to running instances with public IP 
                    and have port open other than 80/443.
        AR-1045 -> Flag Security Groups that allow inbound traffic on ports other than 80/443.
"""

import boto3

ec2_rule_ids = ['AR-309', 'AR-651', 'AR-1044', 'AR-1045']
OPEN_PORT = 22
PROTOCOL = ['tcp', '-1']
IPV4_HOLDER = '0.0.0.0/0'
IPV6_HOLDER = '::/0'
VALID_PORTS = [80, 443]

# should not delete the whole security group but rather just modify the unwanted rule.
want_to_delete_the_whole_security_group = False


def contain_port(sec_group_rule):
    """ Check for open ports in the security group rule.

        Args:
            sec_group_rule (dict):
                Has FromPort and ToPort from which it is identifiers whether it's an open port violation.

        Returns:
            bool: True if open port else false.
    """
    from_port = sec_group_rule['FromPort']
    to_port = sec_group_rule['ToPort']
    return (from_port == -1 and to_port == -1) or (from_port <= OPEN_PORT <= to_port)


def is_tcp(protocol):
    """ Checks if the protocol is TCP or any.

        Args:
            protocol (str):
                protocol of Security group rule.

        Returns:
            bool: True if the port is either not present or is TCP or -1.
    """
    return not protocol or protocol in PROTOCOL


def revoke_or_delete(group_id, sec_group_rule_id):
    """ A filter method to revoke security group rule access from ingress or egress or delete the whole security group.
        It is always better to revoke access.
        Args:
            group_id (str):
                Security group id which is attached to the ec2.
            sec_group_rule_id(str):
                Security group rule Id, under the security group
    """
    if want_to_delete_the_whole_security_group:
        ec2.delete_security_group(GroupId=group_id)
    else:
        revoke_security_group_rules(group_id, sec_group_rule_id)


def revoke_security_group_rules(group_id, sec_group_rule_id):
    """ Revokes the security group rule from the ingress or egress which made the resource public.
        It 1st tries to revoke for ingress and if no ingress with that id found then for egress.
        This is the actual remediation happening to remove the security group rule.
        This is done here as it is not known whether the resulting security group rule id attached to ingress or egress.
        Args:
            group_id (str):
                Security group id which is attached to the ec2.
            sec_group_rule_id(str):
                Security group rule Id, under the security group
    """
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


def get_violating_rules(sec_group_rule):
    result = None
    from_port = sec_group_rule['FromPort']
    to_port = sec_group_rule['ToPort']
    if from_port == to_port:
        if from_port not in VALID_PORTS:
            result = sec_group_rule
    else:
        result = sec_group_rule
    return result


def check_other_port(from_port):
    found = False
    for port in VALID_PORTS:
        if port == from_port:
            found = True
            break
    return not found


def contain_port_other_than(sec_group_rule):
    from_port = sec_group_rule['FromPort']
    to_port = sec_group_rule['ToPort']
    return (from_port == -1 and to_port == -1) or (from_port != to_port) or check_other_port(from_port)


def lambda_handler(event, context, ec2_regions):
    """ Starting function to ec2 remediation for rule present in :ec2_rule_ids:.
        Check if this function can remediate the event.
        If no, returns
        If yes, Iterates over all the regions to check for violating security group rule or any public images,
        and remediate.

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
    """Get the current Account Id of AWS"""
    account_id = boto3.client('sts').get_caller_identity().get('Account')
    if event['eventType'] == 'ALERT' and rule_id in ec2_rule_ids:
        affected_resources = payload_data['affectedResources']
        for reg in ec2_regions:
            global ec2
            ec2 = boto3.client('ec2', region_name=reg)
            if rule_id == ec2_rule_ids[0]:
                """Get all AMI of the account"""
                images = ec2.describe_images(Owners=[account_id])
            else:
                """Get details of all security groups"""
                sec_groups = ec2.describe_security_groups()
            for affected_resource in affected_resources:
                if affected_resource['state'] == "OPEN":
                    try:
                        if rule_id == ec2_rule_ids[0]:
                            image_id = affected_resource['resourceInfo']
                            if images.get('Images'):
                                for image in images['Images']:
                                    """Check if Image Id is the same a affected resource"""
                                    if image['ImageId'] in image_id:
                                        """ Reset image launch permission to default which will 
                                            make it private to that account
                                        """
                                        response = ec2.reset_image_attribute(Attribute='launchPermission',
                                                                             ImageId=image['ImageId'])
                                        print(response)
                        elif rule_id == ec2_rule_ids[1]:
                            for sec_group in sec_groups['SecurityGroups']:
                                if sec_group['GroupId'] in affected_resource['resourceInfo']:
                                    sec_group_rules = ec2.describe_security_group_rules(Filters=[
                                        {
                                            'Name': 'group-id',
                                            'Values': [
                                                sec_group['GroupId']
                                            ]
                                        },
                                    ], MaxResults=512)
                                    if sec_group_rules.get('SecurityGroupRules'):
                                        for sec_group_rule in sec_group_rules['SecurityGroupRules']:
                                            if sec_group_rule.get('IpProtocol'):
                                                if is_tcp(sec_group_rule['IpProtocol']) and contain_port(
                                                        sec_group_rule):
                                                    if (sec_group_rule.get('CidrIpv4')
                                                        and sec_group_rule['CidrIpv4'] == IPV4_HOLDER) or (
                                                            sec_group_rule.get('CidrIpv6')
                                                            and sec_group_rule['CidrIpv6'] == IPV6_HOLDER) or not (
                                                            sec_group_rule.get('CidrIpv6') or sec_group_rule.get(
                                                        'CidrIpv4')):
                                                        revoke_or_delete(sec_group['GroupId'],
                                                                         sec_group_rule['SecurityGroupRuleId'])
                        elif rule_id == ec2_rule_ids[2] or rule_id == ec2_rule_ids[3]:
                            for sec_group in sec_groups['SecurityGroups']:
                                if sec_group['GroupId'] in affected_resource['resourceInfo']:
                                    violating_ports = []
                                    sec_group_rules = ec2.describe_security_group_rules(Filters=[
                                        {
                                            'Name': 'group-id',
                                            'Values': [
                                                sec_group['GroupId']
                                            ]
                                        },
                                    ], MaxResults=512)
                                    if sec_group_rules.get('SecurityGroupRules'):
                                        for sec_group_rule in sec_group_rules['SecurityGroupRules']:
                                            if is_tcp(sec_group_rule['IpProtocol']) and contain_port_other_than(
                                                    sec_group_rule):
                                                if (sec_group_rule.get('CidrIpv4')
                                                    and sec_group_rule['CidrIpv4'] == IPV4_HOLDER) or (
                                                        sec_group_rule.get('CidrIpv6')
                                                        and sec_group_rule['CidrIpv6'] == IPV6_HOLDER):
                                                    viol = get_violating_rules(sec_group_rule)
                                                    if viol:
                                                        violating_ports.append(viol)
                                    if violating_ports:
                                        for violating_port in violating_ports:
                                            revoke_or_delete(sec_group['GroupId'],
                                                             violating_port['SecurityGroupRuleId'])
                    except Exception as e:
                        print(e)
        return "Remediation successful"
