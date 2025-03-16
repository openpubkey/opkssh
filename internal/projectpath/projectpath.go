// Copyright 2025 OpenPubkey
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

// Package projectpath is used internally by the integration tests to get the
// root folder of the opkssh project
package projectpath

import (
	"path/filepath"
	"runtime"
)

// Source: https://stackoverflow.com/a/58294680
var (
	_, b, _, _ = runtime.Caller(0)

	// Root is the root folder of the opkssh project
	Root = filepath.Join(filepath.Dir(b), "../..")
)
