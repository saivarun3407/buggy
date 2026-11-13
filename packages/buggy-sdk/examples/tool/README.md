# buggy-example-tool

A Buggy plugin (tool) scaffolded by ``buggy-sdk plugin new``.

## Build + install

```bash
uv build
pip install dist/*.whl
```

After install, the framework's plugin loader discovers this contribution
via the ``buggy.tools`` entry-point group.

## Test

```bash
pip install buggy-sdk[testing]
pytest
```

Use ``buggy_sdk.testing.FakeBackend`` / ``FakeLLM`` / ``FakeSandbox``
to write hermetic tests that don't need a live framework.
