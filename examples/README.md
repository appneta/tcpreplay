# libtcpreplay examples

Since version 4.6 the Tcpreplay Suite installs **libtcpreplay**, a static
library exposing the same replay engine the `tcpreplay` binary uses, via
`tcpreplay_api.h` (#133). This lets applications replay pcap files and read
live statistics programmatically instead of forking the binary and scraping
its output.

## Building against an installed libtcpreplay

Headers install under `$(includedir)/tcpreplay/` and a pkg-config file is
provided. Because the library is static, ask pkg-config for the private
dependencies too:

```sh
cc replay_stats.c $(pkg-config --cflags --libs --static libtcpreplay) -o replay_stats
sudo ./replay_stats eth0 test.pcap
```

## Examples

* `replay_stats.c` — the minimal flow: `tcpreplay_init()`, configure with the
  `tcpreplay_set_*()` setters and `tcpreplay_add_pcapfile()`, validate/open
  with `tcpreplay_prepare()`, run `tcpreplay_replay()`, then read the final
  counters from `tcpreplay_get_stats()`. The same stats call can be made from
  another thread while the replay is running to stream live statistics.

These examples are compiled as part of the normal build (they are not
installed), so they always match the current API.

## Notes

* Replaying requires the same privileges as the `tcpreplay` binary (root or
  CAP_NET_RAW on Linux).
* The library is currently static-only and its API/ABI follows the suite's
  version, so rebuild your application when upgrading Tcpreplay.
