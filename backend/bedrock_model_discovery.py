"""Bedrock Model Discovery — find and validate available models.

Checks the configured model, tries fallback models, and returns
the best available model for the current account/region.
"""

import logging
import os
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Default fallback models to try (in order of preference)
DEFAULT_FALLBACK_MODELS = [
    "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
    "anthropic.claude-sonnet-4-6",
    "anthropic.claude-haiku-4-5-20251001-v1:0",
    "us.anthropic.claude-3-5-sonnet-20241022-v1:0",
    "us.anthropic.claude-3-5-haiku-20241022-v1:0",
    "anthropic.claude-3-5-sonnet-20240620-v1:0",
    "anthropic.claude-3-haiku-20240307-v1:0",
    "amazon.nova-lite-v1:0",
    "amazon.nova-micro-v1:0",
]


def get_fallback_model_ids() -> List[str]:
    """Get fallback model IDs from env or defaults."""
    env_fallbacks = os.environ.get("BEDROCK_FALLBACK_MODEL_IDS", "")
    if env_fallbacks.strip():
        return [m.strip() for m in env_fallbacks.split(",") if m.strip()]
    return DEFAULT_FALLBACK_MODELS


def validate_model_access(model_id: str, region: str = None) -> Dict[str, str]:
    """Validate that a specific Bedrock model is accessible.
    
    Makes a minimal Converse API call to verify model access.
    
    Returns:
        Dict with status, model_id, message, and fix.
    """
    if not model_id:
        return {
            "status": "misconfigured",
            "model_id": "",
            "message": "No model ID provided",
            "fix": "Set BEDROCK_MODEL_ID in .env",
        }

    region = region or os.environ.get("AWS_REGION", "us-east-1")

    try:
        import boto3
    except ImportError:
        return {
            "status": "misconfigured",
            "model_id": model_id,
            "message": "boto3 not installed",
            "fix": "pip install boto3",
        }

    try:
        client = boto3.client("bedrock-runtime", region_name=region)
        client.converse(
            modelId=model_id,
            messages=[{"role": "user", "content": [{"text": "hi"}]}],
            inferenceConfig={"maxTokens": 1},
        )
        return {
            "status": "connected",
            "model_id": model_id,
            "message": f"Model accessible ({model_id})",
            "fix": "",
        }
    except Exception as e:
        msg = str(e)
        if "AccessDeniedException" in msg or "not authorized" in msg.lower():
            return {
                "status": "access_denied",
                "model_id": model_id,
                "message": f"Access denied for model {model_id}",
                "fix": f"Enable model access in Amazon Bedrock console for {region}. Verify IAM permission bedrock:InvokeModel.",
            }
        elif "ResourceNotFoundException" in msg:
            return {
                "status": "misconfigured",
                "model_id": model_id,
                "message": f"Model not available: {msg[:120]}",
                "fix": f"Model may be legacy/retired or not enabled. Try a different model in {region}.",
            }
        elif "ValidationException" in msg:
            return {
                "status": "misconfigured",
                "model_id": model_id,
                "message": f"Model validation failed: {msg[:120]}",
                "fix": f"Enable on-demand access for this model in Amazon Bedrock console for {region}.",
            }
        elif "NoCredentialsError" in msg or "Unable to locate credentials" in msg:
            return {
                "status": "not_connected",
                "model_id": model_id,
                "message": "AWS credentials not found",
                "fix": "Run: aws configure sso && aws sso login",
            }
        elif "ExpiredToken" in msg:
            return {
                "status": "not_connected",
                "model_id": model_id,
                "message": "AWS credentials expired",
                "fix": "Run: aws sso login --profile <profile>",
            }
        else:
            return {
                "status": "not_connected",
                "model_id": model_id,
                "message": f"Model check failed: {msg[:150]}",
                "fix": f"Verify model access and permissions in {region}",
            }


def select_best_available_model(
    preferred_model_id: str = "",
    region: str = None,
) -> Tuple[Optional[str], Dict[str, str]]:
    """Try the preferred model, then fallbacks, return the first that works.
    
    Returns:
        Tuple of (active_model_id or None, status_dict)
    """
    region = region or os.environ.get("AWS_REGION", "us-east-1")
    fallbacks = get_fallback_model_ids()
    
    # Build ordered list: preferred first, then fallbacks
    models_to_try = []
    if preferred_model_id:
        models_to_try.append(preferred_model_id)
    for fb in fallbacks:
        if fb not in models_to_try:
            models_to_try.append(fb)
    
    tried = []
    last_result = None
    
    for model_id in models_to_try:
        logger.info("Trying Bedrock model: %s", model_id)
        result = validate_model_access(model_id, region)
        tried.append({"model_id": model_id, "status": result["status"]})
        
        if result["status"] == "connected":
            is_fallback = model_id != preferred_model_id
            note = ""
            if is_fallback and preferred_model_id:
                note = f" (configured model '{preferred_model_id}' unavailable; using fallback)"
            return model_id, {
                "status": "connected",
                "model_id": model_id,
                "message": f"Bedrock connected: {model_id}{note}",
                "tried": tried,
                "is_fallback": is_fallback,
                "fix": "",
            }
        
        last_result = result
        
        # If it's a credentials issue, don't try more models
        if result["status"] in ("not_connected",):
            break
    
    # No model worked
    return None, {
        "status": last_result["status"] if last_result else "misconfigured",
        "model_id": preferred_model_id or "",
        "message": last_result["message"] if last_result else "No models available",
        "tried": tried,
        "is_fallback": False,
        "fix": last_result["fix"] if last_result else "Enable a Bedrock model in the console",
    }
