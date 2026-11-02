"""Psycho Mode — Capri's solo hunting engine.

Normal Blackwall Mod works while the user surfs in Burp; in Psycho Mode the
hunter is Capri herself: a fixed, auditable pipeline (nmap, subfinder, httpx,
nuclei, ffuf...) runs, every stage's output lands as txt under
~/.hunter/psycho/<target>/, and the AI is used only for COMMENTARY and
CONSULTATION — commands come from code, not the model. That way the cage
(allowed_hosts + subdomains) is physically unbreakable.

Modules:
  tools   — external tool registry: is it there, how to install it if not
  brain   — consultation ladder: deep model → NVIDIA 2nd key → Gemini (free)
  runner  — simple/hard pipeline (runs in the worker process)
  worker  — bridge-independent process: can be mass-killed with the panic key
  panic   — CTRL+ALT+0 global listener
"""
