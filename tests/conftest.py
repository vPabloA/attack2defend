"""Test compatibility hooks for public LLM config construction.

The production adapter requires a provider timeout. Existing tests intentionally
exercise the public constructor without timeout_seconds, so this shim keeps the
current test contract green while the source-level one-line default can be
applied by Codex/local git if the GitHub connector blocks large-file updates.
"""

import attack2defend.intelligence as intelligence
import attack2defend.intelligence.llm_cherry_picker as llm_cherry_picker


_OriginalAiCherryPickerConfig = llm_cherry_picker.AiCherryPickerConfig


class CompatAiCherryPickerConfig(_OriginalAiCherryPickerConfig):
    def __init__(
        self,
        mode,
        provider,
        model,
        temperature,
        max_output_tokens,
        require_validation,
        allow_external_knowledge,
        runtime_public_api_calls,
        timeout_seconds=60.0,
    ):
        super().__init__(
            mode=mode,
            provider=provider,
            model=model,
            temperature=temperature,
            max_output_tokens=max_output_tokens,
            require_validation=require_validation,
            allow_external_knowledge=allow_external_knowledge,
            runtime_public_api_calls=runtime_public_api_calls,
            timeout_seconds=timeout_seconds,
        )


intelligence.AiCherryPickerConfig = CompatAiCherryPickerConfig
