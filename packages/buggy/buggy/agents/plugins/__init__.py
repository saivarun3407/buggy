"""OSS-shipped plugin-shape bundle — vulnresearch family.

Contains the ``vulnresearch`` main agent and its 5 subagents (scanner,
detector, verifier, patcher, exploiter). Even though this code ships
inside OSS, it is wired the same way an external community / downstream
plugin would be: each subagent's ``SUBAGENT_SPEC`` declares
``bundle="plugins"`` and ``parent_agents=("vulnresearch",)``, and the
specs are registered under the ``buggy.subagents`` entry-point
group in ``pyproject.toml``. This makes vulnresearch the canonical
reference for the community-plugin contract — see
``buggy/plugin_loader.py`` for the loader.
"""
