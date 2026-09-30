import json
import os
import time
import requests


# ============================================================
# LLM PROVIDER
# ============================================================

# Available:
#   "sglang"  -> SGLang OpenAI-compatible server
#   "nvidia"  -> NVIDIA hosted Nemotron
#   "ollama"  -> Local Ollama / Gemma
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "sglang").lower()


# ============================================================
# SGLANG CONFIGURATION
# ============================================================

SGLANG_BASE_URL = "http://192.168.200.23:11650/v1"
SGLANG_CHAT_URL = f"{SGLANG_BASE_URL}/chat/completions"
SGLANG_MODEL = "gemma-4-26b-a4b-it"
SGLANG_TIMEOUT = 600
SGLANG_DEFAULT_API_KEY = os.getenv("SGLANG_API_KEY", "local-sglang-key")


# ============================================================
# OLLAMA CONFIGURATION
# ============================================================

OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
OLLAMA_MODEL = "gemma3:4b"


# ============================================================
# NVIDIA CONFIGURATION
# ============================================================

NVIDIA_URL = "https://integrate.api.nvidia.com/v1/chat/completions"
NVIDIA_MODEL = "nvidia/nemotron-3-super-120b-a12b"
NVIDIA_TIMEOUT = 600


# ============================================================
# GENERIC AI RESPONSE SCHEMA
# ============================================================

AI_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "validity": {
            "type": "string",
            "enum": ["confirmed", "false_positive", "needs_review"]
        },
        "evidence": {
            "type": "array",
            "items": {"type": "string"}
        },
        "risk": {
            "type": "string",
            "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        },
        "confidence": {
            "type": "string",
            "enum": ["LOW", "MEDIUM", "HIGH"]
        },
        "vulnerability_type": {"type": "string"},
        "explanation": {"type": "string"},
        "impact": {"type": "string"},
        "attack_path": {
            "type": "array",
            "items": {"type": "string"}
        },
        "recommended_fix": {"type": "string"},
        "patch_required": {"type": "boolean"}
    },
    "required": [
        "validity",
        "evidence",
        "risk",
        "confidence",
        "vulnerability_type",
        "explanation",
        "impact",
        "attack_path",
        "recommended_fix",
        "patch_required"
    ],
    "additionalProperties": False
}


# ============================================================
# CONTEXTUAL REMEDIATION RESPONSE SCHEMA
# ============================================================

# This is deliberately separate from AI_RESPONSE_SCHEMA.
# remediation_engine.py requires this exact structure.

REMEDIATION_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "applicability": {
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "enum": ["CONFIRMED", "NOT_ESTABLISHED", "UNKNOWN"]
                },
                "reason": {"type": "string"}
            },
            "required": ["status", "reason"],
            "additionalProperties": False
        },
        "risk": {
            "type": "string",
            "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        },
        "conditions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "condition": {"type": "string"},
                    "status": {
                        "type": "string",
                        "enum": [
                            "CONFIRMED",
                            "NOT_SATISFIED",
                            "NOT_ESTABLISHED",
                            "UNKNOWN"
                        ]
                    },
                    "evidence": {"type": "string"},
                    "reason": {"type": "string"}
                },
                "required": ["condition", "status", "evidence", "reason"],
                "additionalProperties": False
            }
        },
        "rce_assessment": {
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "enum": [
                        "CONFIRMED",
                        "NOT_SATISFIED",
                        "NOT_ESTABLISHED",
                        "UNKNOWN"
                    ]
                },
                "reason": {"type": "string"}
            },
            "required": ["status", "reason"],
            "additionalProperties": False
        },
        "information_disclosure_assessment": {
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "enum": [
                        "CONFIRMED",
                        "NOT_SATISFIED",
                        "NOT_ESTABLISHED",
                        "UNKNOWN"
                    ]
                },
                "reason": {"type": "string"}
            },
            "required": ["status", "reason"],
            "additionalProperties": False
        },
        "root_cause": {"type": "string"},
        "remediation": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "action": {"type": "string"},
                    "reason": {"type": "string"},
                    "type": {
                        "type": "string",
                        "enum": [
                            "UPGRADE",
                            "CONFIGURATION",
                            "HARDENING",
                            "DEPENDENCY",
                            "APPLICATION",
                            "VALIDATION"
                        ]
                    }
                },
                "required": ["action", "reason", "type"],
                "additionalProperties": False
            }
        },
        "validation": {
            "type": "array",
            "items": {"type": "string"}
        },
        "confidence": {
            "type": "string",
            "enum": ["LOW", "MEDIUM", "HIGH"]
        },
        "unknowns": {
            "type": "array",
            "items": {"type": "string"}
        }
    },
    "required": [
        "applicability",
        "risk",
        "conditions",
        "rce_assessment",
        "information_disclosure_assessment",
        "root_cause",
        "remediation",
        "validation",
        "confidence",
        "unknowns"
    ],
    "additionalProperties": False
}


# ============================================================
# TOOL SELECTION RESPONSE SCHEMA
# ============================================================

TOOL_SELECTION_SCHEMA = {
    "type": "object",
    "properties": {
        "target_type": {
            "type": "string",
            "enum": ["source_code", "network_host", "mixed_application", "unknown"]
        },
        "selected_tools": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "tool": {
                        "type": "string",
                        "enum": ["semgrep", "trivy", "nmap"]
                    },
                    "reason": {"type": "string"},
                    "target_spec": {"type": "string"}
                },
                "required": ["tool", "reason", "target_spec"],
                "additionalProperties": False
            }
        },
        "analysis_strategy": {"type": "string"}
    },
    "required": ["target_type", "selected_tools", "analysis_strategy"],
    "additionalProperties": False
}


# ============================================================
# SECURITY SYSTEM PROMPTS
# ============================================================

TOOL_SELECTION_SYSTEM_PROMPT = (
    "You are an autonomous cybersecurity orchestrator agent.\n\n"
    "Your goal is to inspect the input artifact or target metadata, "
    "determine what kind of asset it is, and select the optimal defensive tools "
    "from the available toolset: ['semgrep', 'trivy', 'nmap'].\n\n"
    "Tool Guidelines:\n"
    "- 'semgrep': Use for source code files (.py, .js, .ts, .go, .java, etc.) to detect code-level vulnerabilities (SQLi, command injection, XSS, etc.).\n"
    "- 'trivy': Use for dependency manifests (requirements.txt, package.json, pom.xml, go.mod) and filesystem vulnerability audits.\n"
    "- 'nmap': Use for IP addresses, hostnames, or network endpoints to perform service and open-port discovery.\n"
    "- If a project contains BOTH source code and dependency manifests (e.g. Python app with requirements.txt), select BOTH 'semgrep' and 'trivy'.\n\n"
    "Return ONLY a single valid JSON object strictly adhering to the TOOL_SELECTION_SCHEMA."
)

SECURITY_SYSTEM_PROMPT = (
    "You are a cybersecurity vulnerability analysis engine.\n\n"

    "Analyze ONLY the security finding, application information, "
    "configuration evidence, CVE knowledge, and other evidence "
    "provided in the prompt.\n\n"

    "Do not invent application behavior.\n\n"

    "Do not assume that an input is attacker-controlled unless "
    "the provided evidence demonstrates it.\n\n"

    "Distinguish between the existence of a vulnerable code or "
    "component and application-specific exploitability.\n\n"

    "If the evidence is insufficient to determine exploitability, "
    "use the appropriate uncertainty value.\n\n"

    "IMPORTANT: Return exactly ONE JSON object using the following "
    "top-level fields. Do NOT wrap them inside another object such "
    "as 'vulnerability_analysis'.\n\n"

    "{\n"
    '  "validity": "confirmed",\n'
    '  "evidence": ["evidence item"],\n'
    '  "risk": "HIGH",\n'
    '  "confidence": "HIGH",\n'
    '  "vulnerability_type": "CWE-XXX",\n'
    '  "explanation": "Brief explanation based only on the evidence.",\n'
    '  "impact": "Potential impact based only on the evidence.",\n'
    '  "attack_path": [],\n'
    '  "recommended_fix": "Recommended remediation based only on the evidence.",\n'
    '  "patch_required": true\n'
    "}\n\n"

    "The top-level field 'validity' MUST be one of: "
    "'confirmed', 'false_positive', or 'needs_review'.\n\n"

    "The top-level field 'risk' MUST be one of: "
    "'LOW', 'MEDIUM', 'HIGH', or 'CRITICAL'.\n\n"

    "The top-level field 'confidence' MUST be one of: "
    "'LOW', 'MEDIUM', or 'HIGH'.\n\n"

    "The top-level field 'evidence' MUST be an array of strings.\n"
    "The top-level field 'attack_path' MUST be an array of strings.\n"
    "The top-level field 'patch_required' MUST be a boolean.\n\n"

    "Do not use alternative field names such as "
    "'security_risk', 'vulnerability_description', "
    "'vulnerability_cause', 'potential_impact', or "
    "'vulnerability_analysis'.\n\n"

    "Return ONLY the JSON object. Do not use markdown fences. "
    "Do not add explanations outside the JSON object."
)


REMEDIATION_SYSTEM_PROMPT = (
    "You are a cybersecurity vulnerability remediation analyst "
    "inside a controlled security remediation platform.\n\n"

    "Use ONLY the evidence supplied by the user prompt.\n\n"

    "Do not invent facts, application behavior, exploit prerequisites, "
    "libraries, routes, endpoints, configuration, attacker capabilities, "
    "or successful exploitation.\n\n"

    "A vulnerable software version alone does not prove exploitability.\n\n"

    "Preserve NOT_SATISFIED and UNKNOWN conditions exactly when the "
    "evidence does not establish them.\n\n"

    "Distinguish vulnerable version, prerequisites, confirmed exploitability, "
    "and potential impact.\n\n"

    "Use supplied vendor fixed versions exactly. Do not invent fixed versions.\n\n"

    "Do not claim remediation or validation has already succeeded.\n\n"

    "Return ONLY the JSON object required by the remediation schema."
)


# ============================================================
# JSON PARSER
# ============================================================

def parse_llm_json(model_response):
    if not model_response:
        raise RuntimeError("LLM returned an empty response.")

    cleaned = model_response.strip()

    # Remove common Markdown wrappers around JSON.
    if cleaned.startswith("```") and cleaned.endswith("```"):
        lines = cleaned.splitlines()

        # Remove opening ```json / ``` and closing ```
        if lines:
            lines = lines[1:]

        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]

        cleaned = "\n".join(lines).strip()

    # Remove Markdown bold/italic wrappers such as:
    # **{"key": "value"}**
    # *{"key": "value"}*
    while (
        len(cleaned) >= 4
        and cleaned.startswith("**")
        and cleaned.endswith("**")
    ):
        cleaned = cleaned[2:-2].strip()

    while (
        len(cleaned) >= 2
        and cleaned.startswith("*")
        and cleaned.endswith("*")
    ):
        cleaned = cleaned[1:-1].strip()

    try:
        parsed = json.loads(cleaned)

        if isinstance(parsed, dict):
            return parsed

    except json.JSONDecodeError:
        pass

    if cleaned.startswith("{{") and cleaned.endswith("}}"):
        try:
            parsed = json.loads(cleaned[1:-1].strip())

            if isinstance(parsed, dict):
                return parsed

        except json.JSONDecodeError:
            pass

    decoder = json.JSONDecoder()

    for index, character in enumerate(cleaned):

        if character != "{":
            continue

        try:
            parsed, _ = decoder.raw_decode(cleaned[index:])

            if isinstance(parsed, dict):
                return parsed

        except json.JSONDecodeError:
            continue

    raise RuntimeError("LLM returned invalid JSON after cleanup.")


# ============================================================
# SCHEMA SELECTION
# ============================================================

def get_response_schema(task):

    if task == "analysis":
        return AI_RESPONSE_SCHEMA

    if task == "remediation":
        return REMEDIATION_RESPONSE_SCHEMA

    if task == "tool_selection":
        return TOOL_SELECTION_SCHEMA

    raise ValueError(
        f"Unsupported LLM task: {task}. "
        "Expected 'analysis', 'remediation', or 'tool_selection'."
    )


def get_system_prompt(task):

    if task == "analysis":
        return SECURITY_SYSTEM_PROMPT

    if task == "remediation":
        return REMEDIATION_SYSTEM_PROMPT

    if task == "tool_selection":
        return TOOL_SELECTION_SYSTEM_PROMPT

    raise ValueError(
        f"Unsupported LLM task: {task}. "
        "Expected 'analysis', 'remediation', or 'tool_selection'."
    )


# ============================================================
# SGLANG OPENAI-COMPATIBLE MODEL
# ============================================================

def generate_sglang_response(prompt, task="analysis"):

    api_key = os.getenv("LOCAL_LLM_API_KEY", SGLANG_DEFAULT_API_KEY)

    if not api_key:
        raise RuntimeError(
            "LOCAL_LLM_API_KEY environment variable is not set."
        )

    schema = get_response_schema(task)
    system_prompt = get_system_prompt(task)

    payload = {
        "model": SGLANG_MODEL,
        "messages": [
            {
                "role": "system",
                "content": system_prompt
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": 0.1,
        "top_p": 0.95,
        "max_tokens": 5000,
        "stream": False
    }

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    print(f"\nCalling SGLang local model for task: {task}...")
    print(f"Server: {SGLANG_BASE_URL}")
    print(f"Model: {SGLANG_MODEL}")

    max_retries = 3
    retry_delays = [5, 15, 30]

    for attempt in range(max_retries):

        try:

            print(
                f"SGLang request attempt "
                f"{attempt + 1}/{max_retries}"
            )

            response = requests.post(
                SGLANG_CHAT_URL,
                headers=headers,
                json=payload,
                timeout=SGLANG_TIMEOUT
            )

            if response.status_code in [429, 500, 502, 503, 504]:

                print(
                    f"SGLang server returned "
                    f"HTTP {response.status_code}."
                )

                if attempt < max_retries - 1:

                    delay = retry_delays[attempt]

                    print(
                        f"Retrying in {delay} seconds..."
                    )

                    time.sleep(delay)

                    continue

                raise RuntimeError(
                    "SGLang server remained unavailable after "
                    f"{max_retries} attempts.\n"
                    f"HTTP {response.status_code}\n"
                    f"Response: {response.text}"
                )

            if response.status_code == 401:

                raise RuntimeError(
                    "SGLang API authentication failed "
                    "(HTTP 401 Unauthorized). "
                    "Check LOCAL_LLM_API_KEY."
                )

            response.raise_for_status()

            data = response.json()

            choices = data.get("choices")

            if not choices:
                raise RuntimeError(
                    "SGLang response did not contain choices."
                )

            message = choices[0].get("message", {})

            model_response = message.get("content")

            if not model_response:
                raise RuntimeError(
                    "SGLang response did not contain "
                    "assistant content."
                )

            print("\nRAW SGLANG LLM RESPONSE")
            print("=" * 60)
            print(model_response)
            print("=" * 60)

            return parse_llm_json(model_response)

        except requests.exceptions.Timeout:

            print("SGLang request timed out.")

            if attempt < max_retries - 1:

                delay = retry_delays[attempt]

                print(
                    f"Retrying in {delay} seconds..."
                )

                time.sleep(delay)

                continue

            raise RuntimeError(
                f"SGLang LLM request timed out after "
                f"{max_retries} attempts."
            )

        except requests.exceptions.HTTPError as e:

            try:
                error_body = response.text
            except Exception:
                error_body = ""

            raise RuntimeError(
                f"SGLang API request failed:\n"
                f"{e}\n"
                f"Response: {error_body}"
            )

        except requests.exceptions.RequestException as e:

            raise RuntimeError(
                f"Could not communicate with SGLang server: {e}"
            )


# ============================================================
# NVIDIA HOSTED MODEL
# ============================================================

def generate_nvidia_response(prompt, task="analysis"):

    api_key = os.getenv("NVIDIA_API_KEY")

    if not api_key:
        raise RuntimeError(
            "NVIDIA_API_KEY environment variable is not set."
        )

    schema = get_response_schema(task)
    system_prompt = get_system_prompt(task)

    payload = {
        "model": NVIDIA_MODEL,
        "messages": [
            {
                "role": "system",
                "content": system_prompt
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": 0.1,
        "top_p": 0.95,
        "max_tokens": 5000,
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": (
                    "remediation_assessment"
                    if task == "remediation"
                    else "security_assessment"
                ),
                "schema": schema
            }
        },
        "chat_template_kwargs": {
            "enable_thinking": False
        },
        "stream": False
    }

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    print(
        f"\nCalling NVIDIA hosted model for task: {task}..."
    )

    print(
        f"Model: {NVIDIA_MODEL}"
    )

    max_retries = 4
    retry_delays = [5, 15, 30, 60]

    for attempt in range(max_retries):

        try:

            print(
                f"NVIDIA request attempt "
                f"{attempt + 1}/{max_retries}"
            )

            response = requests.post(
                NVIDIA_URL,
                headers=headers,
                json=payload,
                timeout=NVIDIA_TIMEOUT
            )

            if response.status_code in [
                429,
                500,
                502,
                503,
                504
            ]:

                print(
                    f"NVIDIA service returned "
                    f"HTTP {response.status_code}."
                )

                if attempt < max_retries - 1:

                    delay = retry_delays[attempt]

                    print(
                        f"Retrying in {delay} seconds..."
                    )

                    time.sleep(delay)

                    continue

                raise RuntimeError(
                    "NVIDIA hosted service remained unavailable "
                    f"after {max_retries} attempts.\n"
                    f"HTTP {response.status_code}\n"
                    f"Response: {response.text}"
                )

            response.raise_for_status()

            data = response.json()

            choices = data.get("choices")

            if not choices:
                raise RuntimeError(
                    "NVIDIA response did not contain choices."
                )

            message = choices[0].get("message", {})

            model_response = message.get("content")

            if not model_response:
                raise RuntimeError(
                    "NVIDIA response did not contain "
                    "assistant content."
                )

            print("\nRAW NVIDIA LLM RESPONSE")
            print("=" * 60)
            print(model_response)
            print("=" * 60)

            return parse_llm_json(model_response)

        except requests.exceptions.Timeout:

            print("NVIDIA request timed out.")

            if attempt < max_retries - 1:

                delay = retry_delays[attempt]

                print(
                    f"Retrying in {delay} seconds..."
                )

                time.sleep(delay)

                continue

            raise RuntimeError(
                "NVIDIA LLM request timed out."
            )

        except requests.exceptions.HTTPError as e:

            try:
                error_body = response.text
            except Exception:
                error_body = ""

            raise RuntimeError(
                f"NVIDIA API request failed:\n"
                f"{e}\n"
                f"Response: {error_body}"
            )

        except requests.exceptions.RequestException as e:

            raise RuntimeError(
                f"Could not communicate with NVIDIA API: {e}"
            )


# ============================================================
# LOCAL OLLAMA / GEMMA
# ============================================================

def generate_ollama_response(prompt, task="analysis"):

    schema = get_response_schema(task)
    system_prompt = get_system_prompt(task)

    combined_prompt = (
        f"{system_prompt}\n\n"
        "Return ONLY JSON matching this schema:\n"
        f"{json.dumps(schema, ensure_ascii=False)}\n\n"
        f"USER REQUEST:\n{prompt}"
    )

    payload = {
        "model": OLLAMA_MODEL,
        "prompt": combined_prompt,
        "stream": False,
        "format": schema,
        "options": {
            "num_predict": 5000,
            "temperature": 0.1
        }
    }

    print(
        f"\nCalling local Ollama model for task: {task}..."
    )

    print(
        f"Model: {OLLAMA_MODEL}"
    )

    try:

        response = requests.post(
            OLLAMA_URL,
            json=payload,
            timeout=300
        )

        response.raise_for_status()

        data = response.json()

        if data.get("done_reason") == "length":

            raise RuntimeError(
                "Local LLM reached the maximum output "
                "length before completing the response."
            )

        model_response = data.get("response")

        if not model_response:

            raise RuntimeError(
                "Ollama response did not contain "
                "'response' field."
            )

        print("\nRAW OLLAMA LLM RESPONSE")
        print("=" * 60)
        print(model_response)
        print("=" * 60)

        return parse_llm_json(model_response)

    except requests.exceptions.Timeout:

        raise RuntimeError(
            "Local LLM request timed out."
        )

    except requests.exceptions.RequestException as e:

        raise RuntimeError(
            f"Could not communicate with Ollama: {e}"
        )


# ============================================================
# COMMON LLM INTERFACE
# ============================================================

def generate_response(prompt, task="analysis"):

    """
    Common entry point for all LLM callers.

    task="analysis"     -> generic ai_analyzer schema
    task="remediation"  -> contextual remediation schema

    Existing callers that only pass prompt continue to use the
    generic analysis schema. remediation_engine.py passes
    task="remediation" so the model receives the correct schema.
    """

    if task not in {"analysis", "remediation", "tool_selection"}:

        raise ValueError(
            f"Unsupported LLM task: {task}. "
            "Expected 'analysis', 'remediation', or 'tool_selection'."
        )

    if LLM_PROVIDER == "sglang":

        return generate_sglang_response(
            prompt,
            task=task
        )

    if LLM_PROVIDER == "nvidia":

        return generate_nvidia_response(
            prompt,
            task=task
        )

    if LLM_PROVIDER == "ollama":

        return generate_ollama_response(
            prompt,
            task=task
        )

    raise RuntimeError(
        f"Unsupported LLM provider: {LLM_PROVIDER}"
    )