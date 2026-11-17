// Copyright 2026 OpenPubkey
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"net/http"
	"time"
)

// ProviderRequestTimeout bounds every HTTP request opkssh verify makes to an
// OpenID provider: the discovery document, the JWKS and userinfo.
//
// Without it, Go's default client waits as long as the kernel lets a TCP
// connection hang (about two minutes on Linux) when a provider's traffic is
// silently dropped. That is as long as sshd's default LoginGraceTime, so
// the login was dropped before opkssh could fail over to a cached JWKS.
// Fetching a JWKS takes two requests, so a fetch can take up to twice this.
var ProviderRequestTimeout = 10 * time.Second

// NewProviderHTTPClient returns an HTTP client for requests to OpenID
// providers. It uses the default transport, so proxy environment variables
// (for example HTTPS_PROXY set through env_vars in config.yml) still apply.
func NewProviderHTTPClient() *http.Client {
	return &http.Client{Timeout: ProviderRequestTimeout}
}
