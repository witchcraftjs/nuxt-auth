{ lib, pkgs, config, ... }:
let
  cfg = config.postgresConfig;
  hbaConfEntry = import ./hbaConfEntry.nix;
in
{
  options.postgresConfig = {
    enable = lib.mkEnableOption "Enable postgres config.";
    enableDrizzleService = lib.mkEnableOption "Enable drizzle-studio service.";
    host = lib.mkOption {
      type = lib.types.str;
      default = "localhost";
    };
    port = lib.mkOption {
      type = lib.types.int;
      default = 5433;
    };
    user = lib.mkOption {
      type = lib.types.str;
      default = "user";
    };
    database = lib.mkOption {
      type = lib.types.str;
      default = "database";
    };
    passwordEnv = lib.mkOption {
      type = lib.types.str;
      default = "POSTGRES_PASSWORD";
    };
  };
  config = lib.mkIf cfg.enable {
    packages = [
      # beekeeper-studio is nicer but awaiting https://github.com/beekeeper-studio/beekeeper-studio/issues/361
      pkgs.bun
    ];
    env.POSTGRES_HOST = cfg.host;
    env.POSTGRES_PORT = cfg.port;
    env.POSTGRES_USER = cfg.user;
    env.POSTGRES_NAME = cfg.database;
    env.POSTGRES_PASSWORD = builtins.getEnv cfg.passwordEnv;
    services.postgres = {
      enable = true;
      initialDatabases = [{
        name = cfg.database;
      }];
      # note that the init script doesn't seem to initialize them properly
      # the postgres nuxt module takes care of that
      extensions = extensions: [ ];
      initialScript = ''
        CREATE USER "${cfg.user}" WITH ENCRYPTED PASSWORD '${builtins.getEnv cfg.passwordEnv}';
        ALTER USER "${cfg.user}" WITH SUPERUSER;
        ALTER DATABASE "${cfg.database}" OWNER TO "${cfg.user}";
      '';
      listen_addresses = cfg.host;
      port = cfg.port;
      # note that the first matching rule is used
      # so order is important and the match does NOT fallback to the next line
      hbaConf = builtins.concatStringsSep "\n" [
        # \"local\" is for Unix domain socket connections only"
        # specifically allow admin to connect to the socket via password
        (hbaConfEntry [ "local" cfg.database cfg.user "scram-sha-256" ])
        # we must still allow others or the initial config of the db fails"
        # (I think this could be worked around by setting an initial password)"
        (hbaConfEntry [ "local" "all" "all" "peer" ])
        # IPv4 local connections:"
        (hbaConfEntry [ "host" "all" "all" "127.0.0.1/32" "scram-sha-256" ])
        # IPv6 local connections:"
        (hbaConfEntry [ "host" "all" "all" "::1/128" "scram-sha-256" ])
        # Allow replication from localhost, admin w/ padd, or user with the replication privilege."
        (hbaConfEntry [ "local" "replication" cfg.user "scram-sha-256" ])
        (hbaConfEntry [ "local" "replication" "all" "peer" ])
        (hbaConfEntry [ "host" "replication" "all" "127.0.0.1/32" "scram-sha-256" ])
        (hbaConfEntry [ "host" "replication" "all" "::1/128" "scram-sha-256" ])
      ];
    };
    scripts.devPsql = {
      description = "Opens a psql shell as the configured user/host/db/port.";
      exec = "${pkgs.postgresql}/bin/psql -h ${config.env.POSTGRES_HOST} -d ${config.env.POSTGRES_NAME} -U ${config.env.POSTGRES_USER}";
    };
    scripts.devLocalPsql = {
      description = "Opens a \"local\" psql shell via the PGHOST linux socket.";
      exec = "${pkgs.postgresql}/bin/psql -h ${config.env.PGHOST} -d ${config.env.POSTGRES_NAME} -U ${config.env.POSTGRES_USER}";
    };
    scripts.devPingPsql = {
      description = "Pings the postgres server to check if it's up.";
      exec = "${pkgs.postgresql}/bin/pg_isready --dbname=${config.env.POSTGRES_NAME} --host=${config.env.POSTGRES_HOST} --port=${builtins.toString config.env.POSTGRES_PORT}";
    };
    scripts.killPortPostgres.exec = ''
      fuser -k ${builtins.toString config.services.postgres.port}/tcp
    '';
    processes.drizzle-studio = lib.mkIf cfg.enableDrizzleService {
      exec = "pnpm drizzle-kit studio";
      process-compose.availability.max_restarts = 5;
    };
  };
}
