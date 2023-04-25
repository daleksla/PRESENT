# PRESENT
## README

Implementations of the PRESENT algorithm for a Rasberry Pi PICO

### Summary

Two implementations of the PRESENT algorithm located in the `src/` directory - one reference implementation (`present_ref/crypto.*`) and another utilising (32-fold) bitslicing  (`present_bs/crypto.*`).

Testing script, for both, is available against specific test vectors.

Note: this was developed as a team as part of University coursework. This is designed to pass a series of provided tests, not to be used in production. Code was inspired & adapted in part from lecture contents and other sources. I am hosting this here for fun (aka as a cheap backup and to showcase work)

### Building

Run `build.sh`

### Using

Flash the appropriate `.uf2` from the `build/` directory onto your PICO and use the appropriate `test_against_testvectors.py` scripts, supplying the serial port to the PICO.

---

No license, notion of exclusive ownership is indicated or to be inferred whatsoever
