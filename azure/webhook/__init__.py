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
from webhook import AZ_2052
from webhook import AZ_2251
import azure.functions as func

"""
    Rule remediation
        AZ_2052 -> Ensure that 'Automatic provisioning of monitoring agent' is set to 'On'.
        AZ_2251 -> Ensure that a Log Profile exists.
"""


def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')
    try:
        if req.get_body():
            req_body = req.get_json()
            logging.info(req_body)
            if req_body:
                AZ_2052.function_handler(req_body)
                AZ_2251.function_handler(req_body)
    except Exception as e:
        logging.exception(e)
        return func.HttpResponse(
            "This HTTP triggered function FAILED.",
            status_code=500
        )

    return func.HttpResponse(
            "This HTTP triggered function executed successfully.",
            status_code=200
    )
