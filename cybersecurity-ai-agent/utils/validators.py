import re
from typing import Final

# Compile regex patterns for better performance
API_KEY_PATTERN: Final = re.compile(r'^sk-[a-zA-Z0-9]{20,}$')
IP_PATTERN: Final = re.compile(
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
)
URL_PATTERN: Final = re.compile(
    r'^https?://[-\w.]+(?::\d+)?(?:/[\w/_.-]*)?'
    r'(?:\?[\w&=%.-]*)?(?:#\w*)?$'
)

# Dangerous characters to remove in sanitization
DANGEROUS_CHARS: Final = frozenset(['<', '>', '"', "'", '&', ';', '|', '`'])

def validate_api_key(api_key: str) -> bool:
    """
    Validate OpenAI API key format.
    
    Args:
        api_key: String to validate as OpenAI API key
    Returns:
        bool: True if valid, False otherwise
    """
    try:
        return bool(api_key and API_KEY_PATTERN.match(api_key))
    except TypeError:
        return False

def validate_ip_address(ip: str) -> bool:
    """
    Validate IP address format.
    
    Args:
        ip: String to validate as IP address
    Returns:
        bool: True if valid, False otherwise
    """
    try:
        return bool(IP_PATTERN.match(ip))
    except TypeError:
        return False

def validate_url(url: str) -> bool:
    """
    Validate URL format.
    
    Args:
        url: String to validate as URL
    Returns:
        bool: True if valid, False otherwise
    """
    try:
        return bool(URL_PATTERN.match(url))
    except TypeError:
        return False

def sanitize_input(user_input: str) -> str:
    """
    Sanitize user input to prevent injection attacks.
    
    Args:
        user_input: String to sanitize
    Returns:
        str: Sanitized string
    """
    if not isinstance(user_input, str):
        return ""
    
    # Use translate with str.maketrans for better performance
    translation_table = str.maketrans("", "", "".join(DANGEROUS_CHARS))
    return user_input.translate(translation_table).strip()