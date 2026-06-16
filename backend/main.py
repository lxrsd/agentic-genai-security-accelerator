"""Main entry point for the Agentic Security Posture Accelerator."""

import argparse
import os
import sys
from pathlib import Path

from backend.importer import ProwlerImporter
from backend.normalizer import Normalizer
from backend.pillar_mapper import SecurityAreaMapper
from backend.scoring import ScoringEngine
from backend.aws_best_practice_catalog import AWSBestPracticeCatalog
from backend.aws_scoring_engine import AWSBestPracticeScoringEngine
from backend.mcp_server import MCPServer
from backend.api import PostureAPIHandler, start_server
from backend.assistant import SimulatedAssistant
from backend.bedrock_assistant import BedrockAssistant
from backend.mcp_clients import MCPConnectionManager


DEFAULT_DATA_DIR = "sample-data/prowler-output"


def check_connections():
    """Check all service connections and print status report, then exit."""
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass
    
    from backend.preflight import print_preflight
    print_preflight()
    sys.exit(0)


def main():
    """Run the security posture accelerator pipeline and start the server."""
    # Load .env file if python-dotenv is available
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass  # python-dotenv is optional for basic operation

    parser = argparse.ArgumentParser(
        description="Agentic Security Posture Accelerator"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Server port (default: 8080)",
    )
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Host address to bind to (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--data-dir",
        type=str,
        default=DEFAULT_DATA_DIR,
        help="Prowler output directory (default: sample-data/prowler-output)",
    )
    parser.add_argument(
        "--check-connections",
        action="store_true",
        help="Check all service connections and exit",
    )
    args = parser.parse_args()

    # Handle --check-connections mode
    if args.check_connections:
        check_connections()
        return

    data_dir = Path(args.data_dir)
    is_demo_mode = args.data_dir == DEFAULT_DATA_DIR

    print("=" * 60)
    print("  Agentic Security Posture Command Center")
    print("=" * 60)
    print()

    # Step 1: Import findings
    print(f"[1/5] Loading findings from {data_dir}...")
    importer = ProwlerImporter(data_dir)
    raw = importer.load_findings()
    print(f"       Loaded {len(raw)} raw findings")

    # Step 2: Normalize findings
    print("[2/5] Normalizing findings...")
    normalizer = Normalizer()
    normalized = normalizer.normalize_batch(raw)
    print(f"       Normalized {len(normalized)} findings")

    # Step 3: Map to security areas
    print("[3/5] Mapping to security areas...")
    mapper = SecurityAreaMapper()
    pillar_findings = mapper.map_batch(normalized)
    mapped_count = sum(len(v) for v in pillar_findings.values())
    print(f"       Mapped {mapped_count} findings across 5 security areas")

    # Step 4: Initialize AWS Best-Practice Scoring Engine
    print("[4/5] Initializing AWS Best-Practice Scoring Engine...")

    # Create connection manager first (needed for MCP client)
    data_source = "sample-data" if is_demo_mode else str(data_dir)
    connection_manager = MCPConnectionManager(
        findings_count=len(normalized),
        data_source=data_source,
    )

    # Build catalog with MCP client for potential enrichment
    catalog = AWSBestPracticeCatalog(
        aws_knowledge_client=connection_manager.aws_knowledge_client
    )

    # Attempt MCP enrichment
    catalog.enrich_from_mcp()

    # Create the new scoring engine
    engine = AWSBestPracticeScoringEngine(catalog)
    print(f"       Scoring mode: {engine.scoring_mode_display}")

    # Step 5: Calculate posture scores
    print("[5/5] Calculating posture scores...")
    posture = engine.calculate_posture(pillar_findings)
    print(f"       Overall score: {posture.overall_score}/5.0")

    # Create MCP server with computed data
    mcp = MCPServer(engine, posture)

    # Attach connection manager to API handler
    PostureAPIHandler.connection_manager = connection_manager

    # Store scoring metadata on handler for API access
    PostureAPIHandler.scoring_mode = engine.scoring_mode
    PostureAPIHandler.scoring_mode_display = engine.scoring_mode_display

    # Print connection status
    connection_manager.print_connection_report()

    # Create assistant — Bedrock first, simulated only for dev
    bedrock_assistant = BedrockAssistant(
        posture_tools=mcp,
        mcp_connection_manager=connection_manager,
    )

    if bedrock_assistant.is_connected:
        PostureAPIHandler.assistant = bedrock_assistant
        print("  Assistant: Amazon Bedrock (connected)")
    elif os.environ.get("DEV_SIMULATED_ASSISTANT", "false").lower() == "true":
        PostureAPIHandler.assistant = SimulatedAssistant(mcp)
        print("  Assistant: Simulated (DEV mode)")
    else:
        PostureAPIHandler.assistant = bedrock_assistant  # Will return "Not connected" messages
        print("  Assistant: Bedrock not connected (set BEDROCK_ENABLED=true)")

    # Print startup message
    print()
    print(f"Agentic Security Posture Command Center running at http://{args.host}:{args.port}")
    if is_demo_mode:
        print("Mode: Demo (sample data)")
    else:
        print(f"Mode: Connected (custom data path: {data_dir})")
    print()
    print("Press Ctrl+C to stop")
    print()

    # Start HTTP server (blocks until Ctrl+C)
    start_server(mcp, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
