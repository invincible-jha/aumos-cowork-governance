# Architecture — aumos-cowork-governance

## Overview

Governance plugin for multi-agent collaboration environments

This document describes the high-level architecture of aumos-cowork-governance
and the design decisions behind it.

## Component Map

```
aumos-cowork-governance/
  src/aumos_cowork_governance/
    core/        # Domain logic, models, protocols
    plugins/     # Plugin registry and base classes
    cli/         # Click CLI application
```

## Plugin System

aumos-cowork-governance uses a decorator-based plugin registry backed by
``importlib.metadata`` entry-points. This allows third-party packages
(including commercial extensions) to extend the system
without modifying the core.

### Registration at import time

```python
from aumos_cowork_governance.plugins.registry import PluginRegistry
from aumos_cowork_governance.core import BaseProcessor  # example base class

processor_registry: PluginRegistry[BaseProcessor] = PluginRegistry(
    BaseProcessor, "processors"
)

@processor_registry.register("my-processor")
class MyProcessor(BaseProcessor):
    ...
```

### Registration via entry-points

Downstream packages declare plugins in ``pyproject.toml``:

```toml
[aumos_cowork_governance.plugins]
my-processor = "my_package:MyProcessor"
```

Then load them at startup:

```python
processor_registry.load_entrypoints("aumos_cowork_governance.plugins")
```

## Design Principles

- **Dependency injection**: services receive dependencies as constructor
  arguments rather than reaching for globals.
- **Pydantic v2 at boundaries**: all data entering or leaving the system
  is validated via Pydantic models.
- **Async-first**: I/O-bound operations use ``async``/``await``.
- **No hidden globals**: avoid module-level singletons that complicate
  testing and concurrent use.

## Extension Points

| Extension Point | Mechanism |
|----------------|-----------|
| Custom processors | ``PluginRegistry`` entry-points |
| Custom CLI commands | ``click`` group plugins |
| Configuration | Pydantic ``BaseSettings`` |

## Future Work

- [ ] Async streaming support
- [ ] OpenTelemetry tracing
- [ ] gRPC transport option
