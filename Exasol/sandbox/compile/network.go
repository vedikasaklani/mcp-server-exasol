package compile

import (
	"mcp-warden/sandbox/profile"
)

// NetworkConfig is the compiled form of a tool's declared network egress.
//
// It deliberately does not describe a netns/veth/route setup. §6.1 point 4
// frames this as "network namespace ... declared destinations get an
// explicit allowlist via a userspace resolver" — but gVisor's default
// networking is its own userspace netstack, not a conventional Linux
// netns, and there's nothing for veth/route rules to attach to in a form
// that reliably constrains the guest. See design note flag #4.
//
// v0's design instead: the container gets no network interfaces at all
// (Mode is always NetworkModeNone), and any declared destination is
// reachable only through an out-of-sandbox broker process reached over a
// Unix domain socket bind-mounted into the container. The broker enforces
// the allowlist and does DNS resolution itself, so exfiltration over a
// disallowed host or over raw DNS is structurally impossible rather than
// filtered after the fact.
type NetworkConfig struct {
	Mode                NetworkMode
	AllowedDestinations []profile.NetworkDestination
	BrokerSocketPath    string
}

// NetworkMode names the sandbox's network interface configuration.
type NetworkMode string

// NetworkModeNone is the only mode v0 produces: no interfaces, no loopback
// exception carved out for anything but the broker's Unix domain socket.
const NetworkModeNone NetworkMode = "none"

// compileNetwork turns a tool's declared destinations into a NetworkConfig.
// brokerSocketPath is a runtime-level concern (where the broker's socket is
// bind-mounted for this container), not something the profile declares, so
// it's passed in rather than read from the CapabilityProfile.
func compileNetwork(t profile.Tool, brokerSocketPath string) NetworkConfig {
	dests := make([]profile.NetworkDestination, len(t.Network))
	copy(dests, t.Network)

	return NetworkConfig{
		Mode:                NetworkModeNone,
		AllowedDestinations: dests,
		BrokerSocketPath:    brokerSocketPath,
	}
}
