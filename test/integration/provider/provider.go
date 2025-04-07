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

//go:build integration

package provider

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"runtime"
	"time"

	"github.com/openpubkey/opkssh/internal/projectpath"

	"github.com/docker/go-connections/nat"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

type ExampleOpContainer struct {
	testcontainers.Container
	Host string
	Port int
}

func RunExampleOpContainer(ctx context.Context, networkName string, env map[string]string, port string) (*ExampleOpContainer, error) {
	issuerServerPort := fmt.Sprintf("%s/tcp", port)
	req := testcontainers.ContainerRequest{
		FromDockerfile: testcontainers.FromDockerfile{
			Context:       projectpath.Root,
			Dockerfile:    filepath.Join("test", "integration", "provider", "exampleop.Dockerfile"),
			PrintBuildLog: true,
			KeepImage:     true,
		},
		Env:          env,
		ExposedPorts: []string{issuerServerPort},
		Networks: []string{
			networkName,
		},
		ImagePlatform: "linux/" + runtime.GOARCH,
		WaitingFor: wait.ForHTTP("/.well-known/openid-configuration").
			WithPort(nat.Port(issuerServerPort)).
			WithStartupTimeout(10 * time.Second).
			WithMethod(http.MethodGet),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, err
	}

	mappedPort, err := container.MappedPort(ctx, nat.Port(issuerServerPort))
	if err != nil {
		return nil, err
	}
	hostIP, err := container.Host(ctx)
	if err != nil {
		return nil, err
	}
	return &ExampleOpContainer{
		Container: container,
		Host:      hostIP,
		Port:      mappedPort.Int(),
	}, nil
}
