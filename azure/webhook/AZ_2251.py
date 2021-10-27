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
import random
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.identity import DefaultAzureCredential

monitoring_management_log_profile_rule = ['AZ-2251']


def function_handler(event):
    """ Get Monitor management to get the log profiles. If there is no log profile present, crete a resource
        group to add the storage for logs. Once they are created create the log profile with resource group
        and storage id data.

        Args:
            event (dict):
                This is the payload with is sent via Optix, whenever an alert is generated.
    """
    payload_data = event['payloadData']
    rule_id = payload_data['ruleNumber']
    if event['eventType'] == 'ALERT' and rule_id in monitoring_management_log_profile_rule[0]:
        __credentials = DefaultAzureCredential()
        affected_resources = payload_data['affectedResources']
        for affected_resource in affected_resources:
            if affected_resource['state'] == "OPEN":
                resource_info = affected_resource['resourceInfo']
                monitor_management = MonitorManagementClient(credential=__credentials,
                                                             subscription_id=payload_data['accountId'])
                logging.info("Resource Info >>>> : " + resource_info)
                log_profiles = monitor_management.log_profiles
                log_profiles_list = log_profiles.list()
                if log_profiles_list:
                    try:
                        log = log_profiles_list.next()
                        if log.name:
                            logging.info("Already been remediated")
                            return
                    except StopIteration as e:
                        logging.info("Starting remediation")
                    resource_client = ResourceManagementClient(__credentials, payload_data['accountId'])
                    NAME = "remediation_default"
                    LOCATION = "centralus"
                    rg_result = resource_client.resource_groups.create_or_update(NAME, {"location": LOCATION})
                    logging.info("Provisioned resource group : " + rg_result.name)
                    storage_client = StorageManagementClient(__credentials, payload_data['accountId'])
                    STORAGE_ACCOUNT_NAME = None
                    account_result = None
                    for item in storage_client.storage_accounts.list_by_resource_group(NAME):
                        if 'remediationdefault' in item.name:
                            STORAGE_ACCOUNT_NAME = item.name
                            account_result = item
                    if not STORAGE_ACCOUNT_NAME:
                        STORAGE_ACCOUNT_NAME = f"remediationdefault{random.randint(1, 100000):05}"
                        availability_result = storage_client.storage_accounts.check_name_availability(
                            {"name": STORAGE_ACCOUNT_NAME})
                        if availability_result.name_available:
                            poller = storage_client.storage_accounts.begin_create(NAME, STORAGE_ACCOUNT_NAME,
                                                                                  {
                                                                                      "location": LOCATION,
                                                                                      "kind": "StorageV2",
                                                                                      "sku": {"name": "Standard_LRS"}
                                                                                  }
                                                                                  )
                            account_result = poller.result()
                            logging.info(f"Provisioned storage account {account_result.name}")
                        parameters = {
                            "location": "",
                            "locations": [
                                "global"
                            ],
                            "categories": [
                                "Write",
                                "Delete",
                                "Action"
                            ],
                            "retention_policy": {
                                "enabled": True,
                                "days": "365"
                            },
                            "storage_account_id": account_result.id,
                        }
                        result = log_profiles.create_or_update(NAME, parameters)
                        logging.info("Successfully added new log_profile: remediation_default")
