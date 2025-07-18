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
          vendorHash = "sha256-vVJG3ejg/F9RAy4xxHoRFYRb/8qPg2TLV6aO43S0HRE=";
          goSum = ./go.sum;
          meta.mainProgram = "opkssh";
        };
        default = opkssh;
      });

      overlays.default = final: prev: {
        opkssh = self.packages.${final.stdenv.system}.opkssh;
      };

      nixosModules = {
        server = { config, pkgs, lib, ... }: let cfg = config.programs.opkssh; in {
          options.programs.opkssh = {
            enable = lib.options.mkEnableOption "opkssh";
            package = lib.options.mkOption {
              default = pkgs.opkssh;
              type = lib.types.package;
            };
            command.enable = lib.options.mkEnableOption "opkssh command";
            config = {
              # TODO: Replace these options with submodules.
              authorization_rules' = lib.options.mkOption {
                default = "";
                type = lib.types.lines;
              };
              providers' = lib.options.mkOption {
                default = ''
                  https://accounts.google.com 206584157355-7cbe4s640tvm7naoludob4ut1emii7sf.apps.googleusercontent.com 24h
                  https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0 096ce0a3-5e72-4da8-9c86-12924b294a01 24h
                  https://gitlab.com 8d8b7024572c7fd501f64374dec6bba37096783dfcd792b3988104be08cb6923 24h
                '';
                type = lib.types.lines;
              };
            };
          };

          config = lib.modules.mkIf cfg.enable {
            # This config follows the install-linux.sh procedure.
            users = {
              groups.opkssh = {};
              users.opkssh = {
                isSystemUser = true;
                group = config.users.groups.opkssh.name;
              };
            };

            environment = {
              systemPackages = lib.lists.optional cfg.command.enable cfg.package;
              etc = let inherit (config.users) users groups; in {
                "opk/auth_id" = {
                  user = users.opkssh.name;
                  group = groups.opkssh.name;
                  mode = "0640";
                  text = cfg.config.authorization_rules';
                };
                "opk/providers" = {
                  user = users.opkssh.name;
                  group = groups.opkssh.name;
                  mode = "0640";
                  text = cfg.config.providers';
                };
              };
            };

            security.wrappers.opkssh = let inherit (config.users) users groups; in {
              owner = users.root.name;
              group = groups.root.name;
              source = lib.meta.getExe cfg.package;
            };

            services.openssh = {
              # Command path has to be hardcoded unfortunately.
              authorizedKeysCommand = "/run/wrappers/bin/opkssh verify %u %k %t";
              authorizedKeysCommandUser = config.users.users.opkssh.name;
            };

            systemd.tmpfiles.rules = let inherit (config.users) users groups; in [
              "f /var/log/opkssh.log 660 ${users.root.name} ${groups.opkssh.name} -"
            ];
          };
        };
      };
    };
}
