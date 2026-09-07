# PS4/PS5 NID database — attribution

The embedded `aerolib.csv` in this directory is the PS4/PS5 NID → symbol-name
mapping table from the **ps4_module_loader** project by **SocraticBliss**
(contributions by aerosoul, balika011, flatz, and many others).

- Source: https://github.com/SocraticBliss/ps4_module_loader (aerolib.csv)
- License: GPL-3.0 (the same license as Aura), so it is safe to embed.
- Format: one `NID<space>name` record per line, Windows CRLF endings.
- Size: ~97,000 entries, ~3.5 MB.

To contribute new NIDs or fetch a fresher snapshot, obtain `aerolib.csv` from
the upstream project. Setting `AURA_PS4_NID_DB` overrides this embedded copy.
