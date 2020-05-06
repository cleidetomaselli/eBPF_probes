# eBPF_probes
Simple eBPF programs injectable in the linux kernel in order to collect metrics from a probe.

The programs are recommended to be used within the [Polycube](https://github.com/polycube-network/polycube) framework.
 
## How it works
 
The dataplane examples in the src folder work with the [dynmon](https://github.com/polycube-network/polycube/tree/master/src/services/pcn-dynmon) service: the eBPF code has to be dinamically injected into the probe with the dynmon injector tool, which creates a new dynmon cube with the given configuration, attaches it to the selected interface and then injects the selected dataplane.
The file to inject must be a json file with metrics, so the eBPF code must be formatted (for example with a [string escape](https://www.freeformatter.com/json-escape.html#ad-output)) and put in the code field.

### The IP packet counter

This is an example of dataplane which, after the parsing of the ethernet header, analyzes the packet and if the ether type field of the L2 header is equal to 0x0800 (the code for the IPv4 protocol) it increments a counter stored in a BPF_ARRAY.

There is also another version which in addiction counts also the IPv6 packets.

