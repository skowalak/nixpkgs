{ ... }: {
  name = "paisa";
  nodes.machine = {pkgs, ...}: {
    environment.systemPackages = [ pkgs.paisa ];
  };
  testScript = ''
  start_all()

  machine.execute("""
    paisa init
    paisa serve &
  """)

  machine.succeed("""
    curl --location --fail http://localhost:7500
  """)
  '';
}

