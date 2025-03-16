# Contributing to OpenPubkey

Welcome to OpenPubkey SSH! We are so excited you are here. Thank you for your interest in contributing your time and expertise to the project. The following document details contribution guidelines.

# Getting Started

Whether you're addressing an open issue (or filing a new one), fixing a typo in our documentation, adding to core capabilities of the project, or introducing a new use case, anyone from the community is welcome here at OpenPubkey.

## Include Licensing at the Top of Each File

At the top of each file in your commit, please ensure the following is captured in a comment:

` SPDX-License-Identifier: Apache-2.0 `

## Sign Off on Your Commits

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
```
$ git log -1
commit <commit id>
Author: Jane Doe <jane.doe@example.com>
Date:   Thurs Nov 9 06:14:13 2023 -0400

    This is my signed off commit.

    Signed-off-by: Jane Doe <jane.doe@example.com>
```

## Pull Request (PR) Process

OpenPubkey is managed from the `main` branch. To ensure your contribution is reviewed, all pull requests must be made against the `main` branch.

PRs must include a brief summary of what the change is, any issues associated with the change, and any fixes the change addresses. Please include the relevant link(s) for any fixed issues.

Pull requests do not have to pass all automated checks before being opened, but all checks must pass before merging. This can be useful if you need help figuring out why a required check is failing.

Our automated PR checks verify that:

 1. All unit tests pass, which can be done locally by running `go test ./...`.
 2. The code has been formatted correctly, according to `go fmt`.
 3. There are no obvious errors, according to `go vet`.

## Testing OpenPubkey Locally

To build OpenPubkey, ensure you have Go version `>= 1.20` installed. To verify which version you have installed, try `go version`.

To run the [Google example](https://github.com/openpubkey/openpubkey/tree/main/examples/google):
 1. Navigate to the `examples/google/` directory. 
 2. Execute `go build`
 3. Execute `./google login` to generate a valid PK token using Google as your OIDC provider.
 4. Execute `./google sign` to use the PK token generated in (3) to sign a verifiable message.

# Contributing Roles

Contributors include anyone in the technical community who contributes code, documentation, or other technical artifacts to the OpenPubkey project.

Committers are Contributors who have earned the ability to modify (“commit”) source code, documentation or other technical artifacts in a project’s repository. Note that Committers are still required to submit pull requests.

A Contributor may become a Committer by a majority approval of the existing Committers. A Committer may be removed by a majority approval of the other existing Committers.

# Current Committers

The Committers of OpenPubkey are:
1. Ethan Heilman (@EthanHeilman)
2. Jonny Stoten (@jonnystoten)
3. Lucie Mugnier (@lgmugnier)

# Copyright

By contributing to this repository, you agree to license your work under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0). Any work contributed where you are not the original author must display a license header with the original author(s) and source.