Mesh radio V1.0

Install script - **In development**

## Installer.sh

### Running the node installer

The `installer.sh` installer now automatically re-runs itself with
`sudo` when started by a non-root user. This means you can simply
execute the script as your regular user and it will prompt for the
necessary credentials while keeping root access limited to the
installation process itself.

### Providing custom configuration defaults

The installer reads default values from `/etc/default/mesh.conf`. Use the
`--config /path/to/file` argument when launching the installer to load a
different configuration file. An example configuration containing the
current defaults is available in `mesh-settings.conf.example`.

## Topology overview

By default the installer configures:

* `wlan1` as the radio that joins the B.A.T.M.A.N. Adv mesh (`bat0`).
* `wlan0` as a stand-alone access point on a separate subnet (`10.0.0.0/24`).
* `meshctl` as a systemd-managed helper that brings the mesh online on boot.

The mesh backbone is intentionally minimal: `bat0` only enslaves `wlan1`, and the access point remains on its own subnet for management without any bridging or routing glue.

## Reticulum


### Nomad Network


### MeshChat


### Sideband


## Access Point

