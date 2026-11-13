from buggy_core.utils.env import env_flag


def benchmark_skill_sources() -> list[str]:
    """Return extra skill source paths when BENCHMARK_MODE is active."""
    if env_flag("BENCHMARK_MODE"):
        return ["/skills/benchmark/"]
    return []
