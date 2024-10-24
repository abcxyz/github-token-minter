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
    const token = process.env['MINTY_TOKEN'];
    const octokit = github.getOctokit(token);
    await octokit.request('DELETE /installation/token', {
      headers: {
        'X-GitHub-Api-Version': '2022-11-28',
      },
    });
  } catch (err) {
    core.setFailed(err);
  }
}

post();
