"""Command line interface for YaraFlux MCP Client."""

import argparse
import json
import logging
import os
import sys
from typing import Any, Dict, List, Optional

from yarafluxclient.client import YaraFluxClient
from yarafluxclient.exceptions import YaraFluxClientError

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def setup_parser() -> argparse.ArgumentParser:
    """Set up the argument parser.

    Returns:
        Argument parser
    """
    parser = argparse.ArgumentParser(description="YaraFlux MCP Client")
    parser.add_argument(
        "--url",
        help="YaraFlux MCP Server URL",
        default=os.environ.get("YARAFLUX_URL", "http://localhost:8000"),
    )
    parser.add_argument(
        "--username",
        help="Username for authentication",
        default=os.environ.get("YARAFLUX_USERNAME"),
    )
    parser.add_argument(
        "--password",
        help="Password for authentication",
        default=os.environ.get("YARAFLUX_PASSWORD"),
    )
    parser.add_argument(
        "--token", help="JWT token for authentication", default=os.environ.get("YARAFLUX_TOKEN")
    )
    parser.add_argument("--timeout", help="Request timeout in seconds", type=int, default=30)
    parser.add_argument(
        "--output",
        help="Output format (json, pretty)",
        choices=["json", "pretty"],
        default="pretty",
    )
    parser.add_argument("--debug", help="Enable debug logging", action="store_true")

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Auth commands
    auth_parser = subparsers.add_parser("auth", help="Authentication commands")
    auth_subparsers = auth_parser.add_subparsers(
        dest="auth_command", help="Authentication command to execute"
    )

    login_parser = auth_subparsers.add_parser("login", help="Login and get JWT token")
    login_parser.add_argument("--username", help="Username", required=True)
    login_parser.add_argument("--password", help="Password", required=True)

    # Rules commands
    rules_parser = subparsers.add_parser("rules", help="YARA rule management")
    rules_subparsers = rules_parser.add_subparsers(
        dest="rules_command", help="Rules command to execute"
    )

    list_parser = rules_subparsers.add_parser("list", help="List YARA rules")
    list_parser.add_argument("--source", help="Source filter (custom, community)")

    get_parser = rules_subparsers.add_parser("get", help="Get a YARA rule")
    get_parser.add_argument("name", help="Rule name")
    get_parser.add_argument("--source", help="Source (custom, community)", default="custom")
    get_parser.add_argument("--raw", help="Get raw content", action="store_true")

    create_parser = rules_subparsers.add_parser("create", help="Create a new YARA rule")
    create_parser.add_argument("name", help="Rule name")
    create_parser.add_argument("--file", help="YARA rule file")
    create_parser.add_argument("--content", help="YARA rule content")
    create_parser.add_argument("--source", help="Source (custom, community)", default="custom")

    update_parser = rules_subparsers.add_parser("update", help="Update an existing YARA rule")
    update_parser.add_argument("name", help="Rule name")
    update_parser.add_argument("--file", help="YARA rule file")
    update_parser.add_argument("--content", help="YARA rule content")
    update_parser.add_argument("--source", help="Source (custom, community)", default="custom")

    delete_parser = rules_subparsers.add_parser("delete", help="Delete a YARA rule")
    delete_parser.add_argument("name", help="Rule name")
    delete_parser.add_argument("--source", help="Source (custom, community)", default="custom")

    validate_parser = rules_subparsers.add_parser("validate", help="Validate a YARA rule")
    validate_parser.add_argument("--file", help="YARA rule file")
    validate_parser.add_argument("--content", help="YARA rule content")

    import_parser = rules_subparsers.add_parser("import", help="Import ThreatFlux YARA rules")
    import_parser.add_argument("--url", help="GitHub repository URL")
    import_parser.add_argument("--branch", help="Branch name", default="master")

    # Scan commands
    scan_parser = subparsers.add_parser("scan", help="YARA scanning")
    scan_subparsers = scan_parser.add_subparsers(
        dest="scan_command", help="Scan command to execute"
    )

    scan_url_parser = scan_subparsers.add_parser("url", help="Scan a file from a URL")
    scan_url_parser.add_argument("url", help="URL to scan")
    scan_url_parser.add_argument("--rules", help="Comma-separated list of rule names")
    scan_url_parser.add_argument("--timeout", help="Scan timeout in seconds", type=int)

    scan_result_parser = scan_subparsers.add_parser("result", help="Get a scan result")
    scan_result_parser.add_argument("id", help="Scan ID")

    # MCP commands
    mcp_parser = subparsers.add_parser("mcp", help="MCP integration")
    mcp_subparsers = mcp_parser.add_subparsers(dest="mcp_command", help="MCP command to execute")

    mcp_tools_parser = mcp_subparsers.add_parser("tools", help="Get available MCP tools")

    mcp_invoke_parser = mcp_subparsers.add_parser("invoke", help="Invoke an MCP tool")
    mcp_invoke_parser.add_argument("tool", help="Tool name")
    mcp_invoke_parser.add_argument("--params", help="JSON parameters", required=True)

    return parser


def print_output(data: Any, output_format: str = "pretty") -> None:
    """Print output in the specified format.

    Args:
        data: Data to print
        output_format: Output format (json, pretty)
    """
    if output_format == "json":
        print(json.dumps(data))
    else:
        print(json.dumps(data, indent=2, sort_keys=True))


def handle_auth_command(args: argparse.Namespace, client: YaraFluxClient) -> None:
    """Handle authentication commands.

    Args:
        args: Command line arguments
        client: YaraFlux MCP Client
    """
    if args.auth_command == "login":
        token = client.authenticate(args.username, args.password)
        print_output({"token": token}, args.output)
    else:
        print("Unknown auth command:", args.auth_command)
        sys.exit(1)


def handle_rules_command(args: argparse.Namespace, client: YaraFluxClient) -> None:
    """Handle YARA rule management commands.

    Args:
        args: Command line arguments
        client: YaraFlux MCP Client
    """
    if args.rules_command == "list":
        rules = client.list_rules(args.source)
        print_output(rules, args.output)
    elif args.rules_command == "get":
        if args.raw:
            content = client.get_rule_content(args.name, args.source)
            print(content)
        else:
            rule = client.get_rule(args.name, args.source)
            print_output(rule, args.output)
    elif args.rules_command == "create":
        if args.file:
            with open(args.file, "r") as f:
                content = f.read()
        elif args.content:
            content = args.content
        else:
            print("Error: Either --file or --content must be provided")
            sys.exit(1)

        rule = client.create_rule(args.name, content, args.source)
        print_output(rule, args.output)
    elif args.rules_command == "update":
        if args.file:
            with open(args.file, "r") as f:
                content = f.read()
        elif args.content:
            content = args.content
        else:
            print("Error: Either --file or --content must be provided")
            sys.exit(1)

        rule = client.update_rule(args.name, content, args.source)
        print_output(rule, args.output)
    elif args.rules_command == "delete":
        result = client.delete_rule(args.name, args.source)
        print_output(result, args.output)
    elif args.rules_command == "validate":
        if args.file:
            with open(args.file, "r") as f:
                content = f.read()
        elif args.content:
            content = args.content
        else:
            print("Error: Either --file or --content must be provided")
            sys.exit(1)

        result = client.validate_rule(content)
        print_output(result, args.output)
    elif args.rules_command == "import":
        result = client.import_rules(args.url, args.branch)
        print_output(result, args.output)
    else:
        print("Unknown rules command:", args.rules_command)
        sys.exit(1)


def handle_scan_command(args: argparse.Namespace, client: YaraFluxClient) -> None:
    """Handle YARA scanning commands.

    Args:
        args: Command line arguments
        client: YaraFlux MCP Client
    """
    if args.scan_command == "url":
        rule_names = args.rules.split(",") if args.rules else None
        result = client.scan_url(args.url, rule_names, args.timeout)
        print_output(result, args.output)
    elif args.scan_command == "result":
        result = client.get_scan_result(args.id)
        print_output(result, args.output)
    else:
        print("Unknown scan command:", args.scan_command)
        sys.exit(1)


def handle_mcp_command(args: argparse.Namespace, client: YaraFluxClient) -> None:
    """Handle MCP integration commands.

    Args:
        args: Command line arguments
        client: YaraFlux MCP Client
    """
    if args.mcp_command == "tools":
        tools = client.get_mcp_tools()
        print_output(tools, args.output)
    elif args.mcp_command == "invoke":
        params = json.loads(args.params)
        result = client.invoke_mcp_tool(args.tool, params)
        print_output(result, args.output)
    else:
        print("Unknown MCP command:", args.mcp_command)
        sys.exit(1)


def main() -> None:
    """Main entry point for the CLI."""
    parser = setup_parser()
    args = parser.parse_args()

    # Set up logging
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # No command specified
    if not args.command:
        parser.print_help()
        sys.exit(1)

    try:
        # Create client
        client = YaraFluxClient(args.url, args.username, args.password, args.token, args.timeout)

        # Handle commands
        if args.command == "auth":
            handle_auth_command(args, client)
        elif args.command == "rules":
            handle_rules_command(args, client)
        elif args.command == "scan":
            handle_scan_command(args, client)
        elif args.command == "mcp":
            handle_mcp_command(args, client)
        else:
            print("Unknown command:", args.command)
            sys.exit(1)
    except YaraFluxClientError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
