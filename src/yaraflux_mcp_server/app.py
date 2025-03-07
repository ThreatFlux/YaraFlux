"""Main application entry point for YaraFlux MCP Server.

This module initializes the FastAPI application with MCP integration, routers,
middleware, and event handlers.
"""

import logging
import os
import sys
from typing import Any, Dict, List, Optional

import mcp
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from yaraflux_mcp_server.auth import init_user_db
from yaraflux_mcp_server.config import settings
from yaraflux_mcp_server.yara_service import yara_service

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def ensure_directories_exist() -> None:
    """Ensure all required directories exist."""
    # Get directory paths from settings
    directories = [
        settings.STORAGE_DIR,
        settings.YARA_RULES_DIR,
        settings.YARA_SAMPLES_DIR,
        settings.YARA_RESULTS_DIR,
    ]

    # Create each directory
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        logger.info(f"Ensured directory exists: {directory}")

    # Create source subdirectories for rules
    os.makedirs(settings.YARA_RULES_DIR / "community", exist_ok=True)
    os.makedirs(settings.YARA_RULES_DIR / "custom", exist_ok=True)
    logger.info("Ensured rule source directories exist")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application.

    Returns:
        Configured FastAPI application
    """
    # Create FastAPI app
    app = FastAPI(
        title="YaraFlux MCP Server",
        description="Model Context Protocol server for YARA scanning",
        version="0.1.0",
    )

    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # In production, restrict this to known origins
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Add exception handler for YaraError
    @app.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception):
        """Handle generic exceptions."""
        logger.error(f"Unhandled exception: {str(exc)}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": "Internal server error", "detail": str(exc)},
        )

    # Add API routers
    # Import routers here to avoid circular imports
    try:
        from yaraflux_mcp_server.routers import auth_router, rules_router, scan_router

        app.include_router(auth_router, prefix=settings.API_PREFIX)
        app.include_router(rules_router, prefix=settings.API_PREFIX)
        app.include_router(scan_router, prefix=settings.API_PREFIX)
        logger.info("API routers initialized")
    except Exception as e:
        logger.error(f"Error initializing API routers: {str(e)}")

    # Add MCP router
    try:
        # Import MCP tools module
        import yaraflux_mcp_server.mcp_tools  # noqa

        # For MCP 1.3.0 we need to create MCP endpoints manually
        logger.info("Setting up MCP endpoints for MCP 1.3.0")

        import inspect
        import json

        from fastapi import Body

        # Get all registered tools from mcp_tools module
        tools = []
        tool_functions = {}

        # Identify functions decorated with @tool
        for name, func in inspect.getmembers(yaraflux_mcp_server.mcp_tools):
            if hasattr(func, "__mcp_tool__") or hasattr(func, "_tool") or hasattr(func, "tool"):
                logger.info(f"Found MCP tool: {name}")
                # Extract metadata if available
                description = func.__doc__.strip().split("\n")[0] if func.__doc__ else name
                tool_info = {"name": name, "description": description}
                # Create schema from function signature
                sig = inspect.signature(func)
                props = {}
                required = []
                for param_name, param in sig.parameters.items():
                    if param.default is inspect.Parameter.empty:
                        required.append(param_name)
                    props[param_name] = {"type": "string"}

                tool_info["inputSchema"] = {
                    "type": "object",
                    "properties": props,
                    "required": required,
                }

                tools.append(tool_info)
                tool_functions[name] = func

        if tools:
            # Register endpoints for MCP
            @app.get("/mcp/v1/tools")
            async def mcp_get_tools():
                return tools

            @app.post("/mcp/v1/execute")
            async def mcp_execute(data: dict = Body(...)):
                name = data.get("name")
                params = data.get("parameters", {})

                if name not in tool_functions:
                    return JSONResponse(
                        status_code=404, content={"error": f"Tool '{name}' not found"}
                    )

                try:
                    result = tool_functions[name](**params)
                    return {"result": result}
                except Exception as e:
                    logger.error(f"Error executing tool {name}: {str(e)}")
                    return JSONResponse(status_code=500, content={"error": str(e)})

            logger.info(f"Registered {len(tools)} MCP tools: {', '.join(t['name'] for t in tools)}")
        else:
            logger.warning("No MCP tools found. MCP integration will not work.")
    except Exception as e:
        logger.error(f"Error setting up MCP: {str(e)}")
        logger.warning("MCP integration skipped.")

    # Add health check endpoint
    @app.get("/health")
    async def health_check():
        """Health check endpoint."""
        return {"status": "healthy"}

    # Add startup event
    @app.on_event("startup")
    async def startup_event():
        """Initialize application on startup."""
        logger.info("Starting YaraFlux MCP Server")

        # Ensure directories exist
        ensure_directories_exist()
        logger.info("Directory structure verified")

        # Initialize user database
        try:
            init_user_db()
            logger.info("User database initialized")
        except Exception as e:
            logger.error(f"Error initializing user database: {str(e)}")

        # Load YARA rules
        try:
            yara_service.load_rules(include_default_rules=settings.YARA_INCLUDE_DEFAULT_RULES)
            logger.info("YARA rules loaded")
        except Exception as e:
            logger.error(f"Error loading YARA rules: {str(e)}")

    # Add shutdown event
    @app.on_event("shutdown")
    async def shutdown_event():
        """Cleanup on application shutdown."""
        logger.info("Shutting down YaraFlux MCP Server")

    return app


# Create and export the application
app = create_app()

# Define __all__ to explicitly export the app variable
__all__ = ["app"]


if __name__ == "__main__":
    import uvicorn

    # Run the app
    uvicorn.run(
        "yaraflux_mcp_server.app:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG
    )
