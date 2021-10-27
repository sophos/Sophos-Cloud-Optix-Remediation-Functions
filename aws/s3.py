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
    S3 current Rule remediation by this function.
        AR-251 -> Ensure S3 buckets do not allow public read/list permission.
        AR-252 -> Ensure S3 buckets do not allow public read/list bucket ACL permissions.
        AR-267 -> Ensure S3 buckets do not allow public write permission. 
        AR-268 -> Ensure S3 buckets do not allow public write bucket ACL permissions.
"""

import boto3
import ast

s3_acl_rule_ids = ['AR-251', 'AR-252', 'AR-267', 'AR-268']


def check_rule_permission(rule_id, permission):
    """ Check the respective rule breaking the respective permission.

        Args:
            rule_id (str):
                ruleNumber which should match 1 of the rules present in rule_ids for auto-remediation.
            permission (list):
                The permission which S3 has currently and needs to be remediated.

        Returns:
            bool: True if the permission is violating and should be changed and remediated.
    """
    return (rule_id == s3_acl_rule_ids[0] and permission in ['READ', 'FULL_CONTROL']) or (
                rule_id == s3_acl_rule_ids[1] and permission in ['READ_ACP', 'FULL_CONTROL']) or (
                       rule_id == s3_acl_rule_ids[2] and permission in ['WRITE', 'FULL_CONTROL']) or (
                       rule_id == s3_acl_rule_ids[3] and permission in ['WRITE_ACP', 'FULL_CONTROL'])


def lambda_handler(event, context, ec2_regions):
    """ Starting function to s3 remediation for rule present in s3_acl_rule_ids.
        Check if this function can remediate the event.
        If no, returns
        If yes, Iterates over all the regions to check for the violating acl or policy of the bucket.

        If the acl is in violation of the rule:
            then removes that ACL grant from the list of Grants and updates the Access control policy of that bucket.
        else: find the bucket policy for violation and delete the bucket policy if it violates the rule.

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
    if event['eventType'] == 'ALERT':
        payload_data = event['payloadData']
        rule_id = payload_data['ruleNumber']
        if rule_id in s3_acl_rule_ids:
            all_users_grantee = 'http://acs.amazonaws.com/groups/global/AllUsers'
            update_acls = False
            affected_resources = payload_data['affectedResources']
            for reg in ec2_regions:
                global s3
                s3 = boto3.client('s3', region_name=reg)
                for affected_resource in affected_resources:
                    if affected_resource['state'] == "OPEN":
                        try:
                            bucket = affected_resource['resourceInfo']
                            acls = s3.get_bucket_acl(Bucket=bucket)
                            grants = acls['Grants']
                            owner = acls['Owner']
                            for grant in grants:
                                permission = grant['Permission']
                                grantee = grant['Grantee']
                                if grantee['Type'] == 'Group' and grantee['URI'] == all_users_grantee:
                                    update_acls = check_rule_permission(rule_id, permission)

                                if update_acls:
                                    grants.remove(grant)

                            if update_acls:
                                new_acls = {'Grants': grants, 'Owner': owner}
                                response = s3.put_bucket_acl(
                                    Bucket=bucket,
                                    AccessControlPolicy=new_acls
                                )
                                print(str(response))
                            else:
                                s3_policy_handler(bucket)
                        except Exception as e:
                            print(e)

        return "Remediation successful"


def s3_policy_handler(bucket):
    """ Get the bucket policy to check if the policy allows access to everyone.
        If yes, the delete this policy to secure the s3 bucket.

        Args:
            bucket (str):
                This is the bucket name.
    """
    try:
        policy_document = s3.get_bucket_policy(Bucket=bucket)
        policy = ast.literal_eval(policy_document['Policy'])
        statements = policy['Statement']
        print(str(policy_document))
        for statement in statements:
            if 'Allow' == statement['Effect'] and '*' in statement['Resource']:
                response = s3.delete_bucket_policy(Bucket=bucket)
                print(str(response))
    except Exception as e:
        print(e)
