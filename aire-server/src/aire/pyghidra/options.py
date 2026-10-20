"""Small, JVM-independent indexing configuration."""
from dataclasses import dataclass


@dataclass(frozen=True)
class IndexOptions:
    decompile: bool = True
    include_assembly: bool = True
    max_assembly_instructions: int = 200
    max_assembly_characters: int = 20000
    decompile_timeout_seconds: int = 30
    include_strings: bool = True
    include_imports: bool = True
    include_exports: bool = True
    include_call_edges: bool = True
    include_references: bool = True

    def __post_init__(self):
        for name in ('decompile', 'include_assembly', 'include_strings',
                     'include_imports', 'include_exports', 'include_call_edges', 'include_references'):
            if type(getattr(self, name)) is not bool:
                raise ValueError(f'{name} must be a bool')
        for name in ('max_assembly_instructions', 'max_assembly_characters',
                     'decompile_timeout_seconds'):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f'{name} must be a positive integer')
        if self.decompile_timeout_seconds > 2147483647:
            raise ValueError('decompile_timeout_seconds exceeds the Java int range')
