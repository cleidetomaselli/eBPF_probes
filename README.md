# eBPF_probes
Simple eBPF programs injectable in the Polycube framework

Simple eBPF dataplane programs injectable in the linux kernel in order to collect metrics from a
 probe. The programs are recommended to be used within the [Polycube](https://github.com/polycube-network/polycube) framework.
 
## How it works
 
 The dataplane examples in the src folder work with the dynmon service: the eBPF code has to be dinamically injected into the proble with the dynmon injector tool, which creates a new dynmon cube with the given configuration, attaches it to the selected interface and then injects the selected dataplane (a json file).
