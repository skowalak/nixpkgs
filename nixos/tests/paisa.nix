{ ... }: {
  name = "paisa";
  nodes.machine = {pkgs, ...}: {
    environment.systemPackages = [ pkgs.paisa pkgs.killall ];
  };
  testScript = ''
  start_all()

  machine.succeed("""
    paisa serve &
    sleep 10
    curl --location --fail http://localhost:7500
    killall paisa
  """)
  '';
}

