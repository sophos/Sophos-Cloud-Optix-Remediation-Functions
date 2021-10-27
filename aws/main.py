"""
Copyright 2021 Sophos Ltd. All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License");
You may not use this file except in compliance with the License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0. Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied. See the License for the specific language governing permissions and limitations
#under the License.
"""

import AR_1001
import cloudfront
import cloudtrail
import ec2
import remediation_lambda
import rds
import s3
import boto3

"""Get all the regions available to be able to remediate the resource in any region."""
ec2_pre_region = boto3.client('ec2')
ec2_regions = [region['RegionName'] for region in ec2_pre_region.describe_regions()['Regions']]


def lambda_handler(event, context):
    """
        Main function to run all the rules in lambda. This should be the lambda function to be attached to
        Runtime settings -> Handler as main.lambda_handler
    """
    AR_1001.lambda_handler(event, context, ec2_regions)
    cloudfront.lambda_handler(event, context, ec2_regions)
    cloudtrail.lambda_handler(event, context, ec2_regions)
    ec2.lambda_handler(event, context, ec2_regions)
    remediation_lambda.lambda_handler(event, context, ec2_regions)
    rds.lambda_handler(event, context, ec2_regions)
    s3.lambda_handler(event, context, ec2_regions)
