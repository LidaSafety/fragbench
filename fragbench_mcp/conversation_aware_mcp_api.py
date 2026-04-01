"""
Conversation-Aware MCP API

This FastAPI service provides intelligent, dynamic tool loading for conversations.
Instead of loading all 150+ tools, it dynamically selects 3-5 most relevant tools
per conversation and updates them as the conversation context evolves.

Perfect for integration with chat systems, agents, and other conversational AI.
"""

import asyncio
import json
import logging
import uuid
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timezone
from pathlib import Path
import os

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query, Depends, WebSocket
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from contextlib import asynccontextmanager

from dynamic_mcp_toolkit_manager import DynamicMCPToolkitManager, DynamicMCPClient

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Pydantic Models
class ConversationStartRequest(BaseModel):
    conversation_id: str = Field(..., description="Unique conversation identifier")
    initial_context: str = Field(default="", description="Initial conversation context")
    max_tools: int = Field(default=5, ge=1, le=20, description="Maximum tools to load")
    user_id: Optional[str] = Field(default=None, description="User identifier")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")

class ConversationUpdateRequest(BaseModel):
    conversation_id: str = Field(..., description="Conversation identifier")
    new_context: str = Field(..., description="Updated conversation context")
    force_refresh: bool = Field(default=False, description="Force toolkit refresh")

class ToolExecutionRequest(BaseModel):
    conversation_id: str = Field(..., description="Conversation identifier")
    tool_name: str = Field(..., description="Name of tool to execute")
    arguments: Dict[str, Any] = Field(..., description="Tool arguments")
    track_usage: bool = Field(default=True, description="Track tool usage")

class ConversationToolsResponse(BaseModel):
    conversation_id: str
    tools: List[Dict[str, Any]]
    tool_count: int
    context_summary: str
    last_updated: str
    token_savings_estimate: int

class ToolExecutionResponse(BaseModel):
    success: bool
    result: Optional[Any] = None
    error: Optional[str] = None
    tool_id: str
    execution_time: float
    conversation_id: str
    timestamp: str

class ConversationStatsResponse(BaseModel):
    conversation_id: str
    active_tools: int
    max_tools: int
    last_updated: str
    tools: List[Dict[str, Any]]
    context_summary: str

class GlobalOptimizationResponse(BaseModel):
    total_conversations: int
    total_unique_tools_used: int
    most_popular_tools: List[Tuple[str, int]]
    average_tools_per_conversation: float
    token_savings_total: int


# Global instances
toolkit_manager: Optional[DynamicMCPToolkitManager] = None
dynamic_client: Optional[DynamicMCPClient] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan"""
    global toolkit_manager, dynamic_client

    # Startup
    logger.info("Starting Conversation-Aware MCP API")

    toolkit_manager = DynamicMCPToolkitManager(
        neo4j_uri=os.getenv("NEO4J_URI", "neo4j://localhost:7687"),
        neo4j_username=os.getenv("NEO4J_USERNAME", "neo4j"),
        neo4j_password=os.getenv("NEO4J_PASSWORD", "password"),
        jina_api_key=os.getenv("JINA_API_KEY")
    )

    await toolkit_manager.initialize()
    dynamic_client = DynamicMCPClient(toolkit_manager)

    logger.info(f"Initialized with {len(toolkit_manager.tool_registry)} total tools")
    logger.info(f"Connected to {len(toolkit_manager.server_connections)} MCP servers")

    yield

    # Shutdown
    logger.info("Shutting down Conversation-Aware MCP API")
    if toolkit_manager:
        await toolkit_manager.close()


# Create FastAPI app
app = FastAPI(
    title="Conversation-Aware MCP API",
    description="Dynamic, intelligent tool loading for conversations with MCP servers",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_dynamic_client() -> DynamicMCPClient:
    """Dependency to get dynamic client instance"""
    if dynamic_client is None:
        raise HTTPException(status_code=503, detail="Dynamic MCP client not initialized")
    return dynamic_client


def get_toolkit_manager() -> DynamicMCPToolkitManager:
    """Dependency to get toolkit manager instance"""
    if toolkit_manager is None:
        raise HTTPException(status_code=503, detail="Toolkit manager not initialized")
    return toolkit_manager


# Conversation Management Endpoints
@app.post("/conversations/start", response_model=ConversationToolsResponse)
async def start_conversation(
    request: ConversationStartRequest,
    client: DynamicMCPClient = Depends(get_dynamic_client),
    manager: DynamicMCPToolkitManager = Depends(get_toolkit_manager)
):
    """Start a new conversation with intelligent tool selection"""
    try:
        # Create conversation toolkit
        await manager.create_conversation_toolkit(
            request.conversation_id,
            request.initial_context,
            request.max_tools
        )

        # Get optimized tools for LLM
        tools = await client.start_conversation(request.conversation_id, request.initial_context)

        # Calculate token savings (estimate)
        total_tools_available = len(manager.tool_registry)
        tools_loaded = len(tools)
        token_savings = (total_tools_available - tools_loaded) * 100  # Rough estimate

        return ConversationToolsResponse(
            conversation_id=request.conversation_id,
            tools=tools,
            tool_count=tools_loaded,
            context_summary=request.initial_context,
            last_updated=datetime.now(timezone.utc).isoformat(),
            token_savings_estimate=token_savings
        )

    except Exception as e:
        logger.error(f"Failed to start conversation: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/conversations/update", response_model=ConversationToolsResponse)
async def update_conversation(
    request: ConversationUpdateRequest,
    client: DynamicMCPClient = Depends(get_dynamic_client),
    manager: DynamicMCPToolkitManager = Depends(get_toolkit_manager)
):
    """Update conversation context and refresh tool selection"""
    try:
        if request.conversation_id not in manager.conversation_toolkits:
            raise HTTPException(status_code=404, detail="Conversation not found")

        # Update conversation context
        tools = await client.update_conversation(request.conversation_id, request.new_context)

        # Calculate token savings
        total_tools_available = len(manager.tool_registry)
        tools_loaded = len(tools)
        token_savings = (total_tools_available - tools_loaded) * 100

        return ConversationToolsResponse(
            conversation_id=request.conversation_id,
            tools=tools,
            tool_count=tools_loaded,
            context_summary=request.new_context,
            last_updated=datetime.now(timezone.utc).isoformat(),
            token_savings_estimate=token_savings
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update conversation: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/conversations/{conversation_id}/tools", response_model=ConversationToolsResponse)
async def get_conversation_tools(
    conversation_id: str,
    client: DynamicMCPClient = Depends(get_dynamic_client),
    manager: DynamicMCPToolkitManager = Depends(get_toolkit_manager)
):
    """Get current tools for a conversation"""
    try:
        if conversation_id not in manager.conversation_toolkits:
            raise HTTPException(status_code=404, detail="Conversation not found")

        tools = await client.get_available_tools(conversation_id)
        toolkit = manager.conversation_toolkits[conversation_id]

        # Calculate token savings
        total_tools_available = len(manager.tool_registry)
        tools_loaded = len(tools)
        token_savings = (total_tools_available - tools_loaded) * 100

        return ConversationToolsResponse(
            conversation_id=conversation_id,
            tools=tools,
            tool_count=tools_loaded,
            context_summary=toolkit.context_summary,
            last_updated=toolkit.last_updated.isoformat(),
            token_savings_estimate=token_savings
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get conversation tools: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/conversations/execute", response_model=ToolExecutionResponse)
async def execute_tool(
    request: ToolExecutionRequest,
    client: DynamicMCPClient = Depends(get_dynamic_client)
):
    """Execute a tool within a conversation context"""
    try:
        result = await client.call_tool(
            request.conversation_id,
            request.tool_name,
            request.arguments
        )

        return ToolExecutionResponse(
            success=result['success'],
            result=result.get('result'),
            error=result.get('error'),
            tool_id=result['tool_id'],
            execution_time=result.get('execution_time', 0.0),
            conversation_id=request.conversation_id,
            timestamp=datetime.now(timezone.utc).isoformat()
        )

    except Exception as e:
        logger.error(f"Tool execution failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/conversations/{conversation_id}")
async def end_conversation(
    conversation_id: str,
    client: DynamicMCPClient = Depends(get_dynamic_client)
):
    """End a conversation and cleanup resources"""
    try:
        await client.end_conversation(conversation_id)
        return {"message": f"Conversation {conversation_id} ended successfully"}

    except Exception as e:
        logger.error(f"Failed to end conversation: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Analytics and Monitoring Endpoints
@app.get("/conversations/{conversation_id}/stats", response_model=ConversationStatsResponse)
async def get_conversation_stats(
    conversation_id: str,
    manager: DynamicMCPToolkitManager = Depends(get_toolkit_manager)
):
    """Get detailed statistics for a conversation's toolkit"""
    try:
        stats = await manager.get_toolkit_stats(conversation_id)

        if not stats:
            raise HTTPException(status_code=404, detail="Conversation not found")

        return ConversationStatsResponse(**stats)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get conversation stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/optimization/global", response_model=GlobalOptimizationResponse)
async def get_global_optimization(
    manager: DynamicMCPToolkitManager = Depends(get_toolkit_manager)
):
    """Get global toolkit optimization insights"""
    try:
        optimization = await manager.optimize_global_toolkit()

        # Calculate total token savings across all conversations
        total_conversations = optimization['total_conversations']
        avg_tools_per_conv = optimization['average_tools_per_conversation']
        total_tools_available = len(manager.tool_registry)

        token_savings_total = int(total_conversations * (total_tools_available - avg_tools_per_conv) * 100)

        return GlobalOptimizationResponse(
            total_conversations=optimization['total_conversations'],
            total_unique_tools_used=optimization['total_unique_tools_used'],
            most_popular_tools=optimization['most_popular_tools'],
            average_tools_per_conversation=optimization['average_tools_per_conversation'],
            token_savings_total=token_savings_total
        )

    except Exception as e:
        logger.error(f"Failed to get global optimization: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        if toolkit_manager and dynamic_client:
            server_count = len(toolkit_manager.server_connections)
            tool_count = len(toolkit_manager.tool_registry)
            conversation_count = len(toolkit_manager.conversation_toolkits)

            return {
                "status": "healthy",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "servers_connected": server_count,
                "tools_available": tool_count,
                "active_conversations": conversation_count,
                "version": "1.0.0"
            }
        else:
            return {
                "status": "initializing",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }

    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }


@app.get("/servers/status")
async def get_server_status(
    manager: DynamicMCPToolkitManager = Depends(get_toolkit_manager)
):
    """Get status of all MCP server connections"""
    try:
        server_status = []

        for server_name, connection in manager.server_connections.items():
            server_status.append({
                "server_name": server_name,
                "connection_active": connection.connection_active,
                "tools_available": len(connection.available_tools),
                "last_ping": connection.last_ping.isoformat()
            })

        return {
            "servers": server_status,
            "total_servers": len(server_status),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    except Exception as e:
        logger.error(f"Failed to get server status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# WebSocket for real-time toolkit updates
@app.websocket("/conversations/{conversation_id}/ws")
async def conversation_websocket(
    websocket: WebSocket,
    conversation_id: str,
    manager: DynamicMCPToolkitManager = Depends(get_toolkit_manager)
):
    """WebSocket for real-time conversation toolkit updates"""
    await websocket.accept()

    try:
        while True:
            # Wait for context update from client
            data = await websocket.receive_text()
            message = json.loads(data)

            if message.get("type") == "update_context":
                new_context = message.get("context", "")

                # Update toolkit
                await manager.update_conversation_context(conversation_id, new_context)

                # Get updated tools
                tools = await dynamic_client.get_available_tools(conversation_id)

                # Send updated toolkit to client
                response = {
                    "type": "toolkit_updated",
                    "conversation_id": conversation_id,
                    "tools": tools,
                    "tool_count": len(tools),
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }

                await websocket.send_text(json.dumps(response))

    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        await websocket.close()


# Utility endpoints for integration
@app.get("/tools/registry")
async def get_tool_registry(
    limit: int = Query(default=100, ge=1, le=1000),
    server_name: Optional[str] = Query(default=None),
    manager: DynamicMCPToolkitManager = Depends(get_toolkit_manager)
):
    """Get the complete tool registry with filtering options"""
    try:
        tools = list(manager.tool_registry.values())

        # Filter by server if specified
        if server_name:
            tools = [t for t in tools if t['server_name'] == server_name]

        # Sort by usage and limit
        tools.sort(key=lambda t: (t['usage_count'], t['success_rate']), reverse=True)
        tools = tools[:limit]

        return {
            "tools": tools,
            "total_available": len(manager.tool_registry),
            "filtered_count": len(tools),
            "servers": list(set(t['server_name'] for t in manager.tool_registry.values()))
        }

    except Exception as e:
        logger.error(f"Failed to get tool registry: {e}")
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "conversation_aware_mcp_api:app",
        host="0.0.0.0",
        port=8001,
        reload=True,
        log_level="info"
    )