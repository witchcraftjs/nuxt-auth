{

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    devenv.url = "github:cachix/devenv";
    devenv.inputs.nixpkgs.follows = "nixpkgs";
    utils.url = "github:alanscodelog/nix-devenv-utils";
  };

  nixConfig = {
    extra-trusted-public-keys = "devenv.cachix.org-1:w1cLUi8dv3hnoSPGAuibQv+f9TZLr6cv/Hm9XgU50cw=";
    # this must be configured in /etc/nix/nix.conf
    # see https://nix.dev/manual/nix/2.18/command-ref/conf-file#conf-substituters
    extra-substituters = "https://devenv.cachix.org";
  };

  outputs = inputs@{ flake-parts, nixpkgs, devenv, utils, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [
        inputs.devenv.flakeModule
      ];
      systems = nixpkgs.lib.systems.flakeExposed;
      debug = true;
      perSystem = { config, self', inputs', pkgs, system, ... }: {

        # packages.devenv-up = self.devShells.${system}.default.config.procfileScript;

        devenv.shells.default =
          let
          in {
            imports = [
              "${utils}/helpers/killAllPorts.nix"
              "${utils}/baseEnvs/webDevConfig.nix"
              ../nix/postgres.nix
            ];
            postgresConfig = { enable = true; };
            webDevConfig = {
              enable = true;
              secretHttpsCerts = true;
              useNuxt = true;
            };
            processes.drizzle-studio = {
              exec = "pnpm drizzle-kit studio";
              process-compose.availability.max_restarts = 5;
            };
            enterShell = ''
            '';
          };
      };
    };
}
