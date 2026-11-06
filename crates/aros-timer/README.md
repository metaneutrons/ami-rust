# aros-timer

Time and timers for the selected AROS ABI profile, on top of `timer.device`.
`Timer::open` owns the device and its reply port. It reads the monotonic
E-clock (`Timer::now`), the system and up times, sleeps (`Timer::sleep`) and
starts asynchronous alarms (`Timer::start`) whose completion is signalled
through `Timer::signal_mask`, so they can be waited for together with other
signal sources. A running alarm is aborted and reclaimed when it is dropped.

The crate is `no_std`, allocates nothing and is the same on ABI-v1 and
ABI-v11. Measured resolution and sleep overshoot are in the documentation
of the `aros-timer` crate.
