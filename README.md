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

## Mesh topology options

Version 1.0 ships with flexible topology controls that mirror the common
deployment patterns used in community mesh networks:

* **Backbone expansion over Ethernet.** Set `JOIN_ETH_TO_MESH="yes"` in
  `mesh.conf` (or answer *yes* during the installer prompts) to add your
  wired uplink (default `eth0`) into the B.A.T.M.A.N. Adv domain. Wired
  peers then appear as native mesh participants on `bat0`.
* **Client network modes.** The `CLIENT_NETWORK_MODE` toggle accepts
  `bridge`, `routed`, or `nat`:
  * `bridge` attaches the access point (`wlan0`) to a new Linux bridge
    (default `br-mesh`) along with `bat0`, carries DHCP and STP on the
    bridge, and transparently drops Wi-Fi clients onto the mesh backbone.
  * `routed` retains the default subnet separation between the access
    point and the mesh for environments that prefer explicit routing.
  * `nat` enables nftables-based masquerading from the access point
    toward both the mesh (`bat0`) and wired LAN (`eth0`) while turning on
    IPv4/IPv6 forwarding.
* **Bridge hardening.** When bridge mode is used, `BRIDGE_ENABLE_STP`
  and `BRIDGE_VLAN_FILTERING` map directly to 802.1D spanning-tree and
  VLAN-filtering controls, helping prevent L2 loops.
* **Reticulum multi-interface support.** `RETICULUM_INTERFACES`
  generates `AutoInterface` blocks for each listed device (defaults to
  `bat0,eth0,wlan0`), while `RETICULUM_DISCOVERY` toggles path discovery
  for those links in the generated `rnsd` configuration.

The installer still provisions `wlan1` as the mesh radio, `bat0` as the
layer-2 mesh device, and `wlan0` as the local access point, but the
controls above make it easy to mix bridging, routing, and NAT without
editing service files by hand.

