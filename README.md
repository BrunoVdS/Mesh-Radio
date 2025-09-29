Mesh radio V1.0

Install script - **In development**

Running the node installer
-------------------------

The `mesh_node.sh` installer now automatically re-runs itself with
`sudo` when started by a non-root user. This means you can simply
execute the script as your regular user and it will prompt for the
necessary credentials while keeping root access limited to the
installation process itself.

Configuration script
  The Flask web service configuration has been split out into a dedicated helper
  script. After running `mesh_node.sh` (which now only ensures the Flask package
  is installed), execute `scripts/configure_flask.sh` as root to deploy the
  default application stub, environment file, and systemd service. The node
  installer will call this script automatically when it is present, but you can
  also re-run it later if you need to regenerate the configuration.

Data server for client softwater
  To Do

  Update script
    To Do

Future development
  need figuring out
