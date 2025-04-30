# Contributing to OPKSSH

Welcome to OpenPubkey SSH! We are so excited you are here. Thank you for your interest in contributing your time and expertise to the project. The following document details contribution guidelines.

OPKSSH is part of [the OpenPubkey project.](https://github.com/openpubkey/openpubkey/blob/main/CONTRIBUTING.md)

## Getting Started

Whether you're addressing an open issue (or filing a new one), fixing a typo in our documentation, adding to core capabilities of the project, or introducing a new use case, anyone from the community is welcome here at OpenPubkey.

### Include Licensing at the Top of Each File

At the top of each file in your commit, please ensure the following is captured in a comment:

` SPDX-License-Identifier: Apache-2.0 `

### Sign Off on Your Commits

Contributors are required to sign off on their commits. A sign off certifies that you wrote the associated change or have permission to submit it as an open-source patch. All submissions are bound by the [Developer's Certificate of Origin 1.1](https://developercertificate.org/) and [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).

```
Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

Your sign off can be added manually to your commit, i.e., `Signed-off-by: Jane Doe <jane.doe@example.com>`.

Then, you can create a signed off commit using the flag `-s` or `--signoff`:
`$ git commit -s -m "This is my signed off commit."`.

To verify that your commit was signed off, check your latest log output:

```bash
$ git log -1
commit <commit id>
Author: Jane Doe <jane.doe@example.com>
Date:   Thurs Nov 9 06:14:13 2023 -0400

    This is my signed off commit.

    Signed-off-by: Jane Doe <jane.doe@example.com>
```

### Pull Request (PR) Process

OpenPubkey is managed from the `main` branch. To ensure your contribution is reviewed, all pull requests must be made against the `main` branch.

PRs must include a brief summary of what the change is, any issues associated with the change, and any fixes the change addresses. Please include the relevant link(s) for any fixed issues.

Pull requests do not have to pass all automated checks before being opened, but all checks must pass before merging. This can be useful if you need help figuring out why a required check is failing.

Our automated PR checks verify that:

 1. All unit tests pass, which can be done locally by running `go test ./...`.
 2. The code has been formatted correctly, according to `go fmt`.
 3. There are no obvious errors, according to `go vet`.

## Building and Testing

To build with docker run `./hack/build.sh`

To build natively run

```bash
CGO_ENABLED=false go build -v -o opkssh

chmod u+x opkssh
```

### Unit Tests

```bash
go test -v ./...
```

or

```bash
./hack/unit-tests.sh
```

### Integration Tests

To run the integration tests, you need
[Docker installed](https://docs.docker.com/engine/install/)
and running, because the integration tests make use of
[go testcontainers](https://golang.testcontainers.org/).

Then run the integration tests with:

```bash
# Other supported values are 'centos', 'arch'
# See test/integrationtest/ssh_server/ssh_server.go for more details
export OS_TYPE="ubuntu"
go test -tags=integration ./test/integration -timeout=15m -count=1 -v
```
  
or

```bash
./hack/integration-tests.sh
```

## Packaging `opkssh` Locally

`opkssh` leverages on [GoReleaser](https://goreleaser.com/) to simplify the process of building binaries for all supported systems and architectures, as well as creating distribution packages.

Before you begin, ensure you have [GoReleaser installed](https://goreleaser.com/install/) using one of the available installation methods.

To build binaries only, run the following command:

```bash
goreleaser build --clean --snapshot
```

To test the release process, which includes building binaries and distribution packages, use the following command:

```bash
goreleaser release --clean --snapshot
```

All generated files will be located in the `dist/` directory.

If you want to contribute by adding support for a new system, architecture, or improving distribution packaging, refer to the [GoReleaser documentation](https://goreleaser.com/customization/) for guidance to update the [.goreleaser.yaml](.goreleaser.yaml) file.

## Releasing `opkssh`

Releasing `opkssh` is a straightforward process. If you have the appropriate role to make a release, the process involves creating a new Git tag. Once the tag is pushed, the CI/CD pipeline will:

1. Test the code to ensure all checks pass.
2. Execute the `release` workflow, which runs `GoReleaser` to build binaries, create distribution packages, and generate a draft release available on the [GitHub release page](https://github.com/openpubkey/opkssh/releases).

Once the draft release is created, review and update it if necessary. If everything looks good, publish the release to make it available to the community.

## Contributing Roles

Contributors include anyone in the technical community who contributes code, documentation, or other technical artifacts to the OpenPubkey project.
Committers are Contributors who have earned the ability to modify (“commit”) source code, documentation or other technical artifacts in a project’s repository. Note that Committers are still required to submit pull requests.

A Contributor may become a Committer by a majority approval of the existing Committers. A Committer may be removed by a majority approval of the other existing Committers.

### Current Committers

The Committers of OpenPubkey are:

1. Ethan Heilman (@EthanHeilman)
2. Jonny Stoten (@jonnystoten)
3. Lucie Mugnier (@lgmugnier)

## Copyright

By contributing to this repository, you agree to license your work under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0). Any work contributed where you are not the original author must display a license header with the original author(s) and source.
