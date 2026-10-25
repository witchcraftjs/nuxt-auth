{ inputs, pkgs, lib, config, ... }:

let
  project_name = (builtins.fromJSON (builtins.readFile ./package.json)).name;
in
{
  imports = [ inputs.utils.devenvModule ];

  overlays = [
    (final: prev: {
      unstable = import inputs.nixpkgs-unstable { system = prev.system; };
    })
    (final: prev: {
      playwright-test = inputs.playwright.packages.${prev.system}.playwright-test;
      playwright-driver = inputs.playwright.packages.${prev.system}.playwright-driver;
    })
  ];

  dotenv.enable = true;
  dotenv.disableHint = true;

  custom.js.nodejs.package = pkgs.nodejs_24;
  custom.js.pnpm.package = inputs.nixpkgs-unstable.legacyPackages.${pkgs.system}.pnpm;
  custom.js.setupPlaywright = true;
  custom.js.playwrightDriverPackage = pkgs.playwright-driver;
  custom.electron.enabled = true;
  custom.electron.package = pkgs.unstable.electron_42-bin;

  # user has this set globally sometimes, it must NOT be set for things to function correctly inside devenv
  env.ELECTRON_RUN_AS_NODE = "";
  # fallback only if we need to debug with a real postgres db, the playground uses pglite
  # custom.postgres.enabled = true;
  # custom.postgres.database_name = "nuxt-auth";
  # custom.postgres.user = "app";

  packages = with pkgs; [
    actionlint
  ];

  processes.nuxt = {
    ports.http.allocate = 3001;
    exec = ''NODE_OPTIONS="--max-old-space-size=8192" NUXT_PORT=${toString config.processes.nuxt.ports.http.value} pnpm test:server --port ${toString config.processes.nuxt.ports.http.value}'';
  };

  scripts = {
    getPortNuxt = {
      exec = ''
        exec_output=$(devenv processes list "$@" 2>/dev/null | grep nuxt | tail -c 5)

        echo "$exec_output"
        if [ -z "$exec_output" ]; then
            echo "Error: Output is blank" >&2
            exit 1
        fi
      '';
    };
  };
}
