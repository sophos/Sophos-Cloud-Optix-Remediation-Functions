# Copyright 2021 Sophos Ltd. All rights reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0. Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the specific language governing permissions and limitations
# under the License.

import boto3

ec2_pre_region = boto3.client('ec2')
ec2_regions = [region['RegionName'] for region in ec2_pre_region.describe_regions()['Regions']]
redshift = None
redshift_rule_ids = ['AR-261']


def lambda_handler(event, context):
    payload_data = event['payloadData']
    rule_id = payload_data['ruleNumber']
    if event['eventType'] == 'ALERT' and rule_id == redshift_rule_ids[0]:
        affected_resources = payload_data['affectedResources']
        for reg in ec2_regions:
            redshift = boto3.client('redshift', region_name=reg)
            for affected_resource in affected_resources:
                if affected_resource['state'] == "OPEN":
                    try:
                        resource_info = affected_resource['resourceInfo']
                        clusters = redshift.describe_clusters()
                        if clusters and clusters.get('Clusters'):
                            for cluster in clusters['Clusters']:
                                if not cluster['VpcId'] and cluster['PubliclyAccessible']:
                                    if cluster['ClusterIdentifier'] in resource_info:
                                        redshift.modify_cluster(ClusterIdentifier=cluster['ClusterIdentifier'],
                                                                PubliclyAccessible=False)
                    except Exception as e:
                        print(e)
        return "Remediation successful"
