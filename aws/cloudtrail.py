"""
Copyright 2021 Sophos Ltd. All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License");
You may not use this file except in compliance with the License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0. Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied. See the License for the specific language governing permissions and limitations
#under the License.
"""

import boto3
import ast

"""
    cloudtrail current Rule remediation by this function.
        AR-153 -> Ensure the S3 bucket CloudTrail logs are not publicly accessible.
"""

cloud_trail_rule_ids = ['AR-153']
all_users_grantee = 'http://acs.amazonaws.com/groups/global/AllUsers'
auth_users_grantee = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"


def is_org_s3_bucket(bucket, account_id):
    response = s3.head_bucket(Bucket=bucket, ExpectedBucketOwner=account_id)
    return response['ResponseMetadata']['HTTPStatusCode'] == 200


def is_logging(arn):
    response = cloudtrail.get_trail_status(Name=arn)
    return response['IsLogging']


def lambda_handler(event, context, ec2_regions):
    """ Gets the list of trails to find out which associated bucket is violating this rule.
        Before remediation of the bucket policy or ACL, it checks if the bucket belongs
        to the current account and is in Logging state.
        Resources belonging to other accounts can not be remediated.

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
    if event['eventType'] == 'ALERT' and event['payloadData']['alertType'] == 'Policy':

        payload_data = event['payloadData']
        rule_id = payload_data['ruleNumber']
        affected_resources = payload_data['affectedResources']
        for reg in ec2_regions:
            global s3
            s3 = boto3.client('s3', region_name=reg)
            global cloudtrail
            cloudtrail = boto3.client('cloudtrail', region_name=reg)
            for affected_resource in affected_resources:
                if affected_resource['state'] == "OPEN" and rule_id == cloud_trail_rule_ids[0]:
                    try:
                        resource_info = affected_resource['resourceInfo']
                        trails = cloudtrail.list_trails()
                        if trails and trails.get('Trails'):
                            for trail in trails['Trails']:
                                if trail['Name'] in resource_info:
                                    trail_info = cloudtrail.get_trail(Name=trail['TrailARN'])
                                    bucket = trail_info['Trail']['S3BucketName']
                                    if is_org_s3_bucket(bucket, payload_data['accountId']) and is_logging(trail['TrailARN']):
                                        s3_acl_rule_handler(bucket, all_users_grantee)
                                        s3_acl_rule_handler(bucket, auth_users_grantee)
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
        for statement in statements:
            if 'Allow' == statement['Effect'] and '*' in statement['Resource']:
                response = s3.delete_bucket_policy(Bucket=bucket)
                print(str(response))
    except Exception as e:
        print(e)


def s3_acl_rule_handler(bucket, grantee_uri):
    """ If ACL is in violation of the rule.
        Then removes that ACL grant from the list of Grants and updates the Access control policy of that bucket.

        Args:
            bucket (str):
                This is the bucket name.
            grantee_uri (str):
                Group grantee URI
    """
    try:
        update_acls = False
        acls = s3.get_bucket_acl(Bucket=bucket)
        grants = acls['Grants']
        owner = acls['Owner']
        for grant in grants:
            grantee = grant['Grantee']
            if grantee['Type'] == 'Group' and grantee['URI'] == grantee_uri:
                grants.remove(grant)
                update_acls = True

        if update_acls:
            new_acls = {'Grants': grants, 'Owner': owner}
            s3.put_bucket_acl(
                Bucket=bucket,
                AccessControlPolicy=new_acls
            )
    except Exception as e:
        print(e)
        raise e
