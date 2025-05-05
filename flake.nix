# SPDX-License-Identifier: Apache-2.0

{
  description = "Open Pubkey for SSH";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-24.11";
  };

  outputs = { self, nixpkgs }:
    let
      supported-systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      # Helper to provide system-specific attributes
      forSupportedSystems = f: nixpkgs.lib.genAttrs supported-systems (system: f {
        pkgs = import nixpkgs { inherit system; };
      });
    in
    {
      packages = forSupportedSystems ({ pkgs }: rec {
        opkssh = pkgs.buildGoModule {
          name = "opkssh";
          src = self;
          vendorHash = "sha256-6nTRiybsNtP/BiDaNrFEGEGM41BAjGpOyQ0AlQimSE4=";
          goSum = ./go.sum;
        };
        default = opkssh;
      });
    };
}
