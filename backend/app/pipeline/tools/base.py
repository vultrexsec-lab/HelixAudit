from abc import ABC, abstractmethod
from ..context import PipelineContext


class BaseTool(ABC):
    name: str = "base"
    description: str = ""
    order: int = 100  # lower runs earlier

    @abstractmethod
    async def run(self, ctx: PipelineContext) -> PipelineContext:
        """Read ctx, enrich ctx, return ctx."""
        raise NotImplementedError
