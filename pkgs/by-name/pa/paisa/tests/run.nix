{ lib, ... }: {
  name = "paisa";
  nodes.machine = {
  };
  testScript = ''
  start_all()

  machine.execute("""
    ${lib.getExe} init
    ${lib.getExe} serve &
  """)

  machine.succeed("""
    curl --location --fail http://localhost:7500
  """)
  '';

}
