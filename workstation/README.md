# OLA Workstation Kit v1

Source: https://github.com/krzysztofcieciwa07-ship-it/OLA
Pinned commit: 426e781ba6e8bc2c17f6ed3bf1150372d673bc07

Run `.OLA-Workstation.ps1` from PowerShell.

The kit checks Git/Docker, clones the exact SHA, builds the real OLA image, runs pytest, starts the real runtime, executes /agent-run, runs the standalone verifier, tests the append-only tamper control, and writes evidence.

Status semantics: VERIFIED / BLOCKED / UNKNOWN / READY.

A local READY result does not by itself claim that the complete production OLA/NINA/IGOR system is globally verified.
