"""
Copyright 2021 Sophos Ltd. All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License");
You may not use this file except in compliance with the License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0. Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied. See the License for the specific language governing permissions and limitations
#under the License.
"""

import logging
from azure.mgmt.security import SecurityCenter
from azure.identity import DefaultAzureCredential
import requests
import azure.common.cloud as cloud

security_center_auto_provisioning_rule = ['AZ-2052']


def function_handler(event):
    """ Get the location where the security center is and then access it to get the
        auto provisioning settings list. Filter that list where the auto provisioning is 'Off'
        for the affected resource. Change auto provisioning to 'On' and update the settings.

        Args:
            event (dict):
                This is the payload with is sent via Optix, whenever an alert is generated.
    """
    payload_data = event['payloadData']
    rule_id = payload_data['ruleNumber']
    if event['eventType'] == 'ALERT' and rule_id == security_center_auto_provisioning_rule[0]:
        __credentials = DefaultAzureCredential()
        affected_resources = payload_data['affectedResources']
        for affected_resource in affected_resources:
            if affected_resource['state'] == "OPEN":
                resource_info = affected_resource['resourceInfo']
                cloud_env = cloud.get_cli_active_cloud()
                mgmt_url = cloud_env.endpoints.resource_manager
                asc_locations_url = mgmt_url + "/subscriptions/" + payload_data[
                    'accountId'] + "/providers/Microsoft.Security/locations?api-version=2015-06-01-preview"
                azure_access_token = __credentials.get_token(mgmt_url + '/.default')
                r = requests.get(asc_locations_url,
                                 headers={"Authorization": "Bearer " + azure_access_token.token}).json()
                location = r['value'][0]['name']
                print("ASC location:" + location)
                security_center = SecurityCenter(credential=__credentials,
                                                 subscription_id=payload_data['accountId'],
                                                 asc_location=location)
                logging.info("Executed cred with security_center >>>")
                auto_provisioning_settings_operations = security_center.auto_provisioning_settings
                auto_provisioning_settings_list = auto_provisioning_settings_operations.list()
                for auto_provisioning_setting in auto_provisioning_settings_list:
                    logging.info(auto_provisioning_setting.name + " >>>> " + auto_provisioning_setting.type)
                    logging.info(">>>>" + resource_info)
                    logging.info(">>>>" + resource_info in auto_provisioning_setting.id)
                    if resource_info in auto_provisioning_setting.id:
                        auto_provisioning = auto_provisioning_setting.auto_provision
                        if auto_provisioning != 'On':
                            auto_provisioning_setting.auto_provision = 'On'
                            logging.info("Changed auto_provisioning_setting goting to update >>>> ")
                            response = auto_provisioning_settings_operations.create(
                                setting_name=auto_provisioning_setting.name,
                                setting=auto_provisioning_setting)
                            logging.info("Successfully remediated AR-2052: " + response.auto_provision)
