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
    rds current Rule remediation by this function.
        AR-260 -> Ensure RDS snapshots are not publicly accessible. 
"""

import boto3

rds_rule_ids = ['AR-260']


def lambda_handler(event, context, ec2_regions):
    """ The function finds the affected db snapshot and modifies the DB snapshot attribute list and removes the
        public ('all') element from the attribute list.

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
    if event['eventType'] == 'ALERT' and rule_id == rds_rule_ids[0]:
        affected_resources = payload_data['affectedResources']
        for reg in ec2_regions:
            rds = boto3.client('rds', region_name=reg)
            for affected_resource in affected_resources:
                if affected_resource['state'] == "OPEN":
                    try:
                        resource_info = affected_resource['resourceInfo']
                        snapshots = rds.describe_db_snapshots(DBSnapshotIdentifier=resource_info)
                        if snapshots and snapshots.get('DBSnapshots'):
                            for snapshot in snapshots['DBSnapshots']:
                                if snapshot['DBSnapshotIdentifier'] in resource_info:
                                    snapshot_attr = rds.describe_db_snapshot_attributes(
                                        DBSnapshotIdentifier=snapshot['DBSnapshotIdentifier'])
                                    if snapshot_attr:
                                        for attr in snapshot_attr['DBSnapshotAttributesResult']['DBSnapshotAttributes']:
                                            for values in attr['AttributeValues']:
                                                if values.lower() == 'all':
                                                    response = rds.modify_db_snapshot_attribute(
                                                        DBSnapshotIdentifier=snapshot['DBSnapshotIdentifier'],
                                                        AttributeName=attr['AttributeName'],
                                                        ValuesToRemove=[
                                                            values,
                                                        ]
                                                    )
                                                    print(str(response))
                    except Exception as e:
                        print(e)
        return "Remediation successful"
