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

The new topology extensions make it possible to mix and match multiple connectivity strategies without editing the scripts by hand.

### Wired interfaces inside the mesh backbone

Set `BAT_WIRED_INTERFACES="eth0"` (or a space-separated list) in your `mesh.conf` before running the installer. Every interface listed there is added to `bat0` during `meshctl up`, so wired peers participate in the same Layer 2 domain as the wireless mesh. This is the easiest way to have Ethernet nodes share the mesh broadcast domain.

### Bridging the access point onto the mesh

To make `wlan0` clients appear directly on the mesh, enable bridging:

```ini
ENABLE_AP_BRIDGE="yes"
BRIDGE_NAME="br-mesh"
# Optional: override the management IP assigned to the bridge
BRIDGE_IP_CIDR="192.168.0.2/24"
```

When bridging is enabled, `meshctl` automatically creates the Linux bridge, enslaves `bat0` and the access-point interface, applies Spanning Tree (with `BRIDGE_STP=on` by default), and assigns the effective IP address to the bridge. DHCP and DNS services are reconfigured to bind to the bridge so that clients obtain addresses on the mesh network.

### Routed/NAT gateway access point

Leave `ENABLE_AP_BRIDGE="no"` to keep the access point on an isolated subnet. You can still forward traffic into the mesh (or other uplinks) by configuring the new routing controls:

```ini
AP_ROUTING_MODE="route"      # or "nat"
AP_ROUTING_PEERS="bat0 eth0" # interfaces that should receive forwarded traffic
AP_ROUTING_NAT_EGRESS="eth0" # required when AP_ROUTING_MODE=nat
```

`meshctl` enables IP forwarding when routing is active, installs the necessary `iptables` forwarding rules, and optionally adds a MASQUERADE rule for NAT. Routing and bridging modes are mutually exclusive, and the installer will stop if both are requested at once.

## Reticulum


### Nomad Network


### MeshChat


### Sideband


## Access Point

