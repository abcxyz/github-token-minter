/**
 * Copyright 2024 The Authors (see AUTHORS file)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

const core = require('@actions/core');

async function main() {
  try {
    const idToken = core.getInput('id_token');
    const serviceURL = core.getInput('service_url');
    const permissions = core.getInput('requested_permissions');

    const oidcToken = await core.getIDToken('github-token-minter');
    const response = await fetch(`${serviceURL}/token`, {
      method: 'post',
      body: permissions,
      headers: {
        'Content-Type': 'application/json',
        'X-OIDC-Token': oidcToken,
        Authorization: `Bearer ${idToken}`,
      },
    });

    // get the response as text so we can try to parse JSON
    const responseText = await response.text();

    if (response.ok) {
      try {
        // try to parse response as JSON for older versions of github-token-minter
        // expecting `{ "token": "TOKEN" }` format

        const resp = JSON.parse(responseText);
        core.setSecret(resp.token);
        core.setOutput('token', resp.token);
      } catch (err) {
        // we didnt get a JSON response, response body contains the token
        // so just use the response text

        const token = responseText;
        core.setSecret(token);
        core.setOutput('token', token);
        core.exportVariable('MINTY_TOKEN', token);
      }
    } else {
      core.error(`Error response from server ${responseText}`);
      throw new Error(
        `HTTP Error Response: ${response.status} ${response.statusText}`
      );
    }
  } catch (err) {
    core.setFailed(err);
  }
}

main();
