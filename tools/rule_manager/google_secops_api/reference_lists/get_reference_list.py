# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""Retrieve a reference list.

API reference:
https://cloud.google.com/chronicle/docs/reference/rest/v1alpha/projects.locations.instances.referenceLists/get
"""

import os
import time
from typing import Any, Mapping

from google.auth.transport import requests


def get_reference_list(
    http_session: requests.AuthorizedSession,
    resource_name: str,
    view: str | None = "REFERENCE_LIST_VIEW_FULL",
    max_retries: int = 3,
) -> Mapping[str, Any]:
  """Retrieves a reference list.

  Args:
    http_session: Authorized session for HTTP requests.
    resource_name: The resource name of the reference list to retrieve. Format:
      projects/{project}/locations/{location}/instances/{instance}/referenceLists/{reference_list_name}
      view (optional): The scope of fields to populate for the ReferenceList
      being returned. Reference:
      https://cloud.google.com/chronicle/docs/reference/rest/v1alpha/ReferenceListView
    max_retries (optional): Maximum number of times to retry HTTP request if
      certain response codes are returned. For example: HTTP response status
      code 429 (Too Many Requests)

  Returns:
    Content and metadata about the requested reference list.

  Raises:
    requests.exceptions.HTTPError: HTTP request resulted in an error
    (response.status_code >= 400).
  """
  url = f"{os.environ['GOOGLE_SECOPS_API_BASE_URL']}/{resource_name}"
  params = {"view": view}
  response = None

  for _ in range(max_retries + 1):
    response = http_session.request(method="GET", url=url, params=params)

    if response.status_code >= 400:
      print(response.text)

    if response.status_code == 429:
      print("API rate limit exceeded. Sleeping for 60s before retrying")
      time.sleep(60)
    else:
      break

  response.raise_for_status()

  return response.json()