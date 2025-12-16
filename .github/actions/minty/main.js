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
    let headers = {
      'Content-Type': 'application/json',
      'X-OIDC-Token': oidcToken,
    };
    // If an identity token is provided, it pass it along
    if (idToken) {
      headers['Authorization'] = `Bearer ${idToken}`;
    }

    const response = await fetch(`${serviceURL}/token`, {
      method: 'post',
      body: permissions,
      headers: headers,
    });

    // get the response as text so we can try to parse JSON
    const responseText = await response.text();

    if (response.ok) {
      try {
         // try to parse response as JSON for older versions of github-token-minter
         // expecting `{ "token": "TOKEN" }` format
 
         const resp = JSON.parse(responseText);
         if (resp.ok && resp.result) {
            core.setSecret(resp.result);
            core.setOutput('token', resp.result);
            core.exportVariable('MINTY_TOKEN', resp.result);
         } else if (resp.token) {
            core.setSecret(resp.token);
            core.setOutput('token', resp.token);
            core.exportVariable('MINTY_TOKEN', resp.token);
         } else {
            core.warning('Parsed JSON response but did not find token or result field.');
         }
       } catch (err) {
         // we didnt get a JSON response, response body contains the token
         // so just use the response text
 
         const token = responseText;
         core.setSecret(token);
         core.setOutput('token', token);
         core.exportVariable('MINTY_TOKEN', token);
       }
     } else {
        try {
           const resp = JSON.parse(responseText);
           if (resp.ok === false && resp.message) {
              core.error(`Server Error [${resp.code || 'UNKNOWN'}]: ${resp.message}`);
           } else {
              core.error(`Error response from server: ${responseText}`);
           }
        } catch (e) {
           core.error(`Error response from server: ${responseText}`);
        }
       throw new Error(
         `HTTP Error Response: ${response.status} ${response.statusText}`
       );
     }
  } catch (err) {
    core.setFailed(err);
  }
}

main();
