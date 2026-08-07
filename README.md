# 🚀 DNS Relay - Multi-thread Exploration

**I acknowledge that the attempt of trying to implement multi-thread is a total failure, because it doesn't fit the scenario and performs even worse than single thread ones.**

- `SO_REUSEPORT` does not fit our testing scenario, since it always allocate the packet to same pthread. Maybe it's problem is that we always send packet from and to `127.0.0.1` via `lo`.
- Polling performs good, but its design is even worse, since it occupies 100% of all CPU cores.

---

**So just use the stable single thread version in `master` branch.**

> *"The best design is not the most complex one — it's the one that fits the problem."*
