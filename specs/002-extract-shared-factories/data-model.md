# Data Model: Extract Shared Adapter & Strategy Factories

**Feature**: 002-extract-shared-factories
**Date**: 2026-03-20

## Overview

This is a pure refactor — no new data entities are introduced. The factories operate on existing domain and infrastructure types.

## Existing Entities (unchanged)

### TargetConfig
- **Location**: `ziran/domain/entities/target.py`
- **Purpose**: Configuration for remote agent targets (URL, protocol, auth, etc.)
- **Used by**: `load_remote_adapter()` factory

### ProtocolType
- **Location**: `ziran/domain/entities/target.py`
- **Purpose**: Enum of supported protocols (rest, openai, mcp, a2a, browser, auto)
- **Used by**: `load_remote_adapter()` for adapter selection

### BaseAgentAdapter
- **Location**: `ziran/domain/interfaces/adapter.py`
- **Purpose**: Abstract base for all agent adapters (the port)
- **Returned by**: All adapter factory functions

### CampaignStrategy (Protocol)
- **Location**: `ziran/application/strategies/protocol.py`
- **Purpose**: Protocol defining strategy interface
- **Returned by**: `build_strategy()` factory

### BaseLLMClient
- **Location**: `ziran/infrastructure/llm/base.py`
- **Purpose**: Abstract LLM client interface
- **Accepted by**: `build_strategy()` for LLM-adaptive variant

## Factory Function Signatures

### load_remote_adapter
- **Input**: `target_path: str`, `protocol_override: str | None`
- **Output**: `BaseAgentAdapter` (concrete: HttpAgentAdapter or BrowserAgentAdapter)

### load_agent_adapter
- **Input**: `framework: str`, `agent_path: str`
- **Output**: `BaseAgentAdapter` (concrete: LangChain/CrewAI/Bedrock/AgentCore adapter)

### build_strategy
- **Input**: `strategy_name: str`, `stop_on_critical: bool`, `llm_client: BaseLLMClient | None`
- **Output**: `CampaignStrategy` (concrete: Fixed/Adaptive/LLMAdaptive strategy)
