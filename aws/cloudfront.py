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
    cloudfront current Rule remediation by this function.
        AR-207 -> Detect the use of secure web origins with secure protocols for CloudFront.
"""

import boto3

cloudfront_rule_ids = ['AR-207']


def lambda_handler(event, context, ec2_regions):
    """ Gets the list of all distributions to check if origin protocol policy is not https-only and
        the ssl protocol has TLSv1 in it's list of protocols.

        Remediation is for both the above by changing the origin and updating the distribution for cloudfront.

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
    has_changed = False
    if event['eventType'] == 'ALERT' and rule_id == cloudfront_rule_ids[0]:
        affected_resources = payload_data['affectedResources']
        for reg in ec2_regions:
            cloudfront = boto3.client('cloudfront', region_name=reg)
            for affected_resource in affected_resources:
                if affected_resource['state'] == "OPEN":
                    try:
                        resource_info = affected_resource['resourceInfo']
                        all_distributions = cloudfront.list_distributions()
                        for distribution in all_distributions['DistributionList']['Items']:
                            if distribution['Id'] in resource_info and distribution.get('Origins'):
                                origins = distribution['Origins']
                                for origin in origins['Items']:
                                    if origin.get('CustomOriginConfig'):
                                        if origin.get('CustomOriginConfig').get('OriginProtocolPolicy'):
                                            if "https-only" != origin['CustomOriginConfig']['OriginProtocolPolicy']:
                                                origin['CustomOriginConfig']['OriginProtocolPolicy'] = 'https-only'
                                                has_changed = True
                                        if origin.get('CustomOriginConfig').get('OriginSslProtocols') and \
                                                origin['CustomOriginConfig']['OriginSslProtocols'] is not None and (
                                                origin['CustomOriginConfig']['OriginSslProtocols'][
                                                    'Items'] is not None and
                                                "TLSv1" in origin['CustomOriginConfig']['OriginSslProtocols']['Items']):
                                            list_items = origin['CustomOriginConfig']['OriginSslProtocols']['Items']
                                            list_items.remove("TLSv1")
                                            # Append needs to be done because update distribution needs same size
                                            # list in OriginSslProtocols...
                                            list_items.append("SSLv3")
                                            origin['CustomOriginConfig']['OriginSslProtocols']['Items'] = list_items
                                            has_changed = True
                                        if has_changed:
                                            dist = cloudfront.get_distribution_config(Id=distribution['Id'])
                                            dist['DistributionConfig']['Origins'] = origins
                                            response = cloudfront.update_distribution(
                                                DistributionConfig=dist['DistributionConfig'], Id=distribution['Id'],
                                                IfMatch=dist['ETag'])
                                            print(str(response))
                    except Exception as e:
                        print(e)
        return "Remediation successful"
