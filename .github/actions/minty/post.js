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
const github = require('@actions/github');

async function post() {
  try {
    const token = core.getState('MINTY_TOKEN');
    if (!token) {
      core.info('No token found to delete in this step.');
      return;
    }
    const octokit = github.getOctokit(token);
    await octokit.request('DELETE /installation/token', {
      headers: {
        'X-GitHub-Api-Version': '2022-11-28',
      },
    });
  } catch (err) {
    if (err.status === 401 || (err.message && err.message.includes('Bad credentials'))) {
      core.info('Token was already invalid or deleted. Suppressing error.');
    } else {
      core.info(`Unexpected error during cleanup: ${err.message}`);
      core.setFailed(err);
    }
  }
}

post();
