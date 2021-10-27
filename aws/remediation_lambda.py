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
    lambda current Rule remediation by this function.
        AR-1004 -> Ensure Lambda Functions are not publicly accessible.
"""

import boto3
import ast

rds_rule_ids = ['AR-1004']
open_principal = ['*', 'aws']


def is_open_principle(principal):
    return principal and principal in open_principal or (
            principal.get('Service') and principal['Service'].lower() in open_principal)


def lambda_handler(event, context, ec2_regions):
    """ The function finds the affected lambda and removes the statement in the function permission which has
        open principle i.e. either public(*) or logged-in AWS user (AWS)

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
        for reg in ec2_regions:
            aws_lambda = boto3.client('lambda', region_name=reg)
            affected_resources = payload_data['affectedResources']
            for affected_resource in affected_resources:
                if affected_resource['state'] == "OPEN":
                    try:
                        resource_info = affected_resource['resourceInfo']
                        all_functions = []
                        next_marker = None
                        while True:
                            if next_marker:
                                list_functions = aws_lambda.list_functions(Marker=next_marker)
                            else:
                                list_functions = aws_lambda.list_functions()
                            if list_functions and list_functions['Functions']:
                                all_functions.append(list_functions['Functions'])
                                if list_functions.get('NextMarker'):
                                    next_marker = list_functions['NextMarker']
                            if not next_marker:
                                break

                        for function in [item for sublist in all_functions for item in sublist]:
                            function_policy = None
                            try:
                                if function['FunctionName'] in resource_info:
                                    function_policy = aws_lambda.get_policy(FunctionName=function['FunctionName'])
                            except Exception as e:
                                print(e)
                            if function_policy and function_policy.get('Policy'):
                                policy = ast.literal_eval(function_policy['Policy'])
                                statements = policy.get('Statement')
                                if statements:
                                    for statement in statements:
                                        principal = statement.get('Principal')
                                        if is_open_principle(principal):
                                            response = aws_lambda.remove_permission(
                                                FunctionName=function['FunctionName'],
                                                StatementId=statement['Sid'])
                                            print(str(response))
                    except Exception as e:
                        print(e)
        return "Remediation successful"
