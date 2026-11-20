# Source baseline

MeshCore Hardened began with a source snapshot of [SaveMeshcore](https://github.com/aigarslv/SaveMeshcore), which adds repeater filters to [MeshCore](https://github.com/meshcore-dev/MeshCore).

- Source revision: [`b9b71db0d949682f59540fa979d15cee83be7fc8`](https://github.com/aigarslv/SaveMeshcore/commit/b9b71db0d949682f59540fa979d15cee83be7fc8), selected from the SaveMeshcore `main` branch.
- [Source archive](https://codeload.github.com/aigarslv/SaveMeshcore/tar.gz/b9b71db0d949682f59540fa979d15cee83be7fc8) SHA-256: `5e275d988f993a24e9a7da47f3fd75350e97c165c1437157fbaa3e708262dd25`.
- Project repository: [WarDaddyLT/MeshCore-Hardened](https://github.com/WarDaddyLT/MeshCore-Hardened).

The archive was imported into the project's own Git repository. The initial import keeps the upstream source, licenses, repeater build check and native test workflow. It omits the inherited release, upstream synchronization, scheduled maintenance and Pages workflows, the upstream multi-firmware PR workflow, and the upstream domain and funding settings. The project branding was updated in the README, repeater CLI reference, docs configuration and Ethernet CLI banner.

Use the pinned revision for future comparisons. Review and document any later upstream imports before applying them.

The ThinkNode M8 repeater build fix from the source snapshot's `platformio.local.ini` lives in the board's versioned configuration. The inherited native test workflow runs on manual dispatch during feature development.
