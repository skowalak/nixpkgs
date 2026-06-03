{ pkgs, ... }:
let

  ca_key = mailerCerts.ca.key;
  ca_pem = mailerCerts.ca.cert;

  bundle =
    pkgs.runCommand "bundle"
      {
        nativeBuildInputs = [ pkgs.minica ];
      }
      ''
        minica -ca-cert ${ca_pem} -ca-key ${ca_key} \
          -domains localhost
        install -Dm444 -t $out localhost/{key,cert}.pem
      '';

  mailerCerts = import ../common/acme/server/snakeoil-certs.nix;
  mailerDomain = mailerCerts.domain;
  testUser = "alice";
  testPassword = "AliceSuperSecretPassword123!";
  testEmail = "alice@example.com";

  synapseClientId = "02H8PKNWKKRPCBW4YGH1RWV279";
  synapseClientSecret = "test_synapse_client_secret";
  matrixSecret = "test_matrix_shared_secret_0123456789abcdef";

  listeners = [
    {
      port = 8448;
      bind_addresses = [
        "127.0.0.1"
        "::1"
      ];
      type = "http";
      tls = true;
      x_forwarded = false;
      resources = [
        {
          names = [
            "client"
          ];
          compress = true;
        }
        {
          names = [
            "federation"
          ];
          compress = false;
        }
      ];
    }
  ];

in
{

  name = "matrix-authentication-service";
  meta = {
    inherit (pkgs.matrix-synapse.meta) maintainers;
  };

  nodes = {
    # Since 0.33.0, matrix-synapse doesn't allow underscores in server names
    serverpostgres =
      {
        pkgs,
        nodes,
        config,
        ...
      }:
      let
        mailserverIP = nodes.mailserver.networking.primaryIPAddress;
      in
      {
        services.matrix-synapse = {
          enable = true;
          extras = [ "oidc" ];
          settings = {
            inherit listeners;
            database = {
              name = "psycopg2";
              args.password = "synapse";
            };
            redis = {
              enabled = true;
              host = "localhost";
              port = config.services.redis.servers.matrix-synapse.port;
            };
            tls_certificate_path = "${bundle}/cert.pem";
            tls_private_key_path = "${bundle}/key.pem";
            public_baseurl = "https://example.com";
            email = {
              smtp_host = mailerDomain;
              smtp_port = 25;
              require_transport_security = true;
              notif_from = "matrix <matrix@${mailerDomain}>";
              app_name = "Matrix";
            };

            # Delegate authentication to MAS
            experimental_features.msc3861 = {
              enabled = true;
              issuer = "http://localhost:8080/";
              client_id = synapseClientId;
              client_auth_method = "client_secret_basic";
              client_secret = synapseClientSecret;
              admin_token = matrixSecret;
            };
          };
        };

        services.matrix-authentication-service = {
          enable = true;
          createDatabase = false;
          settings = {
            http.public_base = "http://localhost:8080/";

            matrix = {
              homeserver = "serverpostgres";
              endpoint = "https://localhost:8448/";
              secret_file = "/var/lib/matrix-authentication-service/matrix_secret";
            };

            database.uri = "postgresql:///matrix-authentication-service?host=/run/postgresql&user=matrix-authentication-service";

            secrets = {
              encryption_file = "/var/lib/matrix-authentication-service/encryption";
              keys = [
                {
                  kid = "rsa-4096";
                  key_file = "/var/lib/matrix-authentication-service/key_rsa_4096";
                }
              ];
            };

            clients = [
              {
                client_id = synapseClientId;
                client_secret = synapseClientSecret;
                client_auth_method = "client_secret_basic";
              }
            ];
          };
        };

        systemd.services.matrix-authentication-service.preStart = ''
          echo -n '${matrixSecret}' > /var/lib/matrix-authentication-service/matrix_secret
          echo -n '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' > /var/lib/matrix-authentication-service/encryption
          ${pkgs.openssl}/bin/openssl genrsa -out /var/lib/matrix-authentication-service/key_rsa_4096 4096
        '';

        services.postgresql = {
          enable = true;
          authentication = pkgs.lib.mkOverride 10 ''
            local all all trust
            host all all 127.0.0.1/32 trust
            host all all ::1/128 trust
          '';

          # The database name and user are configured by the following options:
          #   - services.matrix-synapse.database_name
          #   - services.matrix-synapse.database_user
          #
          # The values used here represent the default values of the module.
          initialScript = pkgs.writeText "synapse-init.sql" ''
            CREATE ROLE "matrix-synapse" WITH LOGIN PASSWORD 'synapse';
            CREATE DATABASE "matrix-synapse" WITH OWNER "matrix-synapse"
              TEMPLATE template0
              LC_COLLATE = "C"
              LC_CTYPE = "C";

            CREATE ROLE "matrix-authentication-service" WITH LOGIN;
            CREATE DATABASE "matrix-authentication-service" WITH OWNER "matrix-authentication-service"
              TEMPLATE template0
              LC_COLLATE = "C"
              LC_CTYPE = "C";
          '';
        };

        services.redis.servers.matrix-synapse = {
          enable = true;
          port = 6380;
        };

        networking.extraHosts = ''
          ${mailserverIP} ${mailerDomain}
        '';

        security.pki.certificateFiles = [
          mailerCerts.ca.cert
          ca_pem
        ];

        environment.systemPackages =
          let
            sendTestMailStarttls = pkgs.writeScriptBin "send-testmail-starttls" ''
              #!${pkgs.python3.interpreter}
              import smtplib
              import ssl

              ctx = ssl.create_default_context()

              with smtplib.SMTP('${mailerDomain}') as smtp:
                smtp.ehlo()
                smtp.starttls(context=ctx)
                smtp.ehlo()
                smtp.sendmail('matrix@${mailerDomain}', '${testEmail}', 'Subject: Test STARTTLS\n\nTest data.')
                smtp.quit()
            '';

            obtainTokenAndRegisterEmail =
              let
                # adding the email through the API is quite complicated as it involves more than one step and some
                # client-side calculation
                insertEmailForAlice = pkgs.writeText "alice-email.sql" ''
                  INSERT INTO user_threepids (user_id, medium, address, validated_at, added_at) VALUES ('${testUser}@serverpostgres', 'email', '${testEmail}', '1629149927271', '1629149927270');
                '';
              in
              pkgs.writeScriptBin "obtain-token-and-register-email" ''
                #!${pkgs.runtimeShell}
                set -o errexit
                set -o pipefail
                set -o nounset
                su postgres -c "psql -d matrix-synapse -f ${insertEmailForAlice}"
                # With MAS, we might not be able to use Synapse's requestToken endpoint for password auth
                # curl --fail -XPOST 'https://localhost:8448/_matrix/client/r0/account/password/email/requestToken' -d '{"email":"${testEmail}","client_secret":"foobar","send_attempt":1}' -v
              '';
          in
          [
            sendTestMailStarttls
            pkgs.matrix-synapse
            pkgs.matrix-authentication-service
            obtainTokenAndRegisterEmail
          ];
      };

    # test mail delivery
    mailserver = args: {
      security.pki.certificateFiles = [
        mailerCerts.ca.cert
      ];

      networking.firewall.enable = false;

      services.postfix = {
        enable = true;
        enableSubmission = true;

        # blackhole transport
        transport = "example.com discard:silently";

        settings.main = {
          myhostname = "${mailerDomain}";
          # open relay for subnet
          mynetworks_style = "subnet";
          debug_peer_level = "10";
          smtpd_relay_restrictions = [
            "permit_mynetworks"
            "reject_unauth_destination"
          ];

          # disable obsolete protocols, something old versions of twisted are still using
          smtpd_tls_protocols = "TLSv1.3, TLSv1.2, !TLSv1.1, !TLSv1, !SSLv2, !SSLv3";
          smtpd_tls_mandatory_protocols = "TLSv1.3, TLSv1.2, !TLSv1.1, !TLSv1, !SSLv2, !SSLv3";
          smtpd_tls_chain_files = [
            "${mailerCerts.${mailerDomain}.key}"
            "${mailerCerts.${mailerDomain}.cert}"
          ];
        };
      };
    };

    serversqlite = args: {
      services.matrix-synapse = {
        enable = true;
        extras = [ "oidc" ];
        settings = {
          inherit listeners;
          database.name = "sqlite3";
          tls_certificate_path = "${bundle}/cert.pem";
          tls_private_key_path = "${bundle}/key.pem";

          # Delegate authentication to MAS
          experimental_features.msc3861 = {
            enabled = true;
            issuer = "http://localhost:8080/";
            client_id = synapseClientId;
            client_auth_method = "client_secret_basic";
            client_secret = synapseClientSecret;
            admin_token = matrixSecret;
          };
        };
      };

      services.postgresql = {
        authentication = pkgs.lib.mkOverride 10 ''
          local all all trust
          host all all 127.0.0.1/32 trust
          host all all ::1/128 trust
        '';
      };

      services.matrix-authentication-service = {
        enable = true;
        createDatabase = true;
        settings = {
          http.public_base = "http://localhost:8080/";

          matrix = {
            homeserver = "serversqlite";
            endpoint = "https://localhost:8448/";
            secret_file = "/var/lib/matrix-authentication-service/matrix_secret";
          };

          database.uri = "postgresql:///matrix-authentication-service?host=/run/postgresql&user=matrix-authentication-service";

          secrets = {
            encryption_file = "/var/lib/matrix-authentication-service/encryption";
            keys = [
              {
                kid = "rsa-4096";
                key_file = "/var/lib/matrix-authentication-service/key_rsa_4096";
              }
            ];
          };

          clients = [
            {
              client_id = synapseClientId;
              client_secret = synapseClientSecret;
              client_auth_method = "client_secret_basic";
            }
          ];
        };
      };

      systemd.services.matrix-authentication-service.preStart = ''
        echo -n '${matrixSecret}' > /var/lib/matrix-authentication-service/matrix_secret
        echo -n '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' > /var/lib/matrix-authentication-service/encryption
        ${pkgs.openssl}/bin/openssl genrsa -out /var/lib/matrix-authentication-service/key_rsa_4096 4096
      '';

      security.pki.certificateFiles = [
        mailerCerts.ca.cert
        ca_pem
      ];

      environment.systemPackages = [ pkgs.matrix-authentication-service ];
    };
  };

  testScript = ''
    start_all()
    mailserver.wait_for_unit("postfix.service")
    serverpostgres.succeed("send-testmail-starttls")
    serverpostgres.wait_for_unit("matrix-synapse.service")
    serverpostgres.wait_for_unit("matrix-authentication-service.service")
    serverpostgres.wait_until_succeeds(
        "curl --fail -L --cacert ${ca_pem} https://localhost:8448/"
    )
    serverpostgres.wait_until_succeeds(
        "journalctl -u matrix-synapse.service | grep -q 'Connected to redis'"
    )
    serverpostgres.require_unit_state("postgresql.target")
    serverpostgres.wait_for_open_port(8080)
    serverpostgres.wait_for_open_port(8081)

    serverpostgres.succeed(
        "mas_config=$(systemctl cat matrix-authentication-service.service | grep -o '/nix/store/.*-config\\.yaml' | head -n 1) && "
        "cd /tmp && mas-cli -c $mas_config manage register-user -y -p ${testPassword} ${testUser}"
    )

    serverpostgres.succeed(
        "curl --fail -s -X POST http://localhost:8080/_matrix/client/r0/login "
        "-H 'Content-Type: application/json' "
        "-d '{\"type\":\"m.login.password\",\"identifier\":{\"type\":\"m.id.user\",\"user\":\"${testUser}\"},\"password\":\"${testPassword}\"}' | grep access_token"
    )

    serverpostgres.succeed("obtain-token-and-register-email")
    serversqlite.wait_for_unit("matrix-synapse.service")
    serversqlite.wait_for_unit("matrix-authentication-service.service")
    serversqlite.wait_until_succeeds(
        "curl --fail -L --cacert ${ca_pem} https://localhost:8448/"
    )
    serversqlite.succeed("[ -e /var/lib/matrix-synapse/homeserver.db ]")
    serversqlite.wait_for_open_port(8080)
    serversqlite.wait_for_open_port(8081)

    serversqlite.succeed(
        "mas_config=$(systemctl cat matrix-authentication-service.service | grep -o '/nix/store/.*-config\\.yaml' | head -n 1) && "
        "cd /tmp && mas-cli -c $mas_config manage register-user -y -p ${testPassword} ${testUser}"
    )
    serversqlite.succeed(
        "curl --fail -s -X POST http://localhost:8080/_matrix/client/r0/login "
        "-H 'Content-Type: application/json' "
        "-d '{\"type\":\"m.login.password\",\"identifier\":{\"type\":\"m.id.user\",\"user\":\"${testUser}\"},\"password\":\"${testPassword}\"}' | grep access_token"
    )
  '';

}
