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

## Creating a full mesh
We are creating a complete mesh using all network interfaces at hand.
Mesh is created on bat0 using wlan1, and we are routing in the access point wlan0 and the internet eth0 in to the mesh by using routing.

### B.A.T.M.A.N. Advanced mesh (bat0, wlan1) 
Creating a mesh network called bat0 and adding wlan 1 to the mesh.

## Access point (wlan0)
Access point for EUD and othe devices to connect to the Raspberry Pi.
  IP: 10.0.0.1/24

DHCP IP range for devices: 10.0.0.100-200

## Internet access
Eth0 is routed in to the mesh and if one node (or more) has internet access on their eth0 hardware the mesh has internet connection.

## Reticulum


### Nomad Network


### MeshChat


### Sideband


## Access Point

