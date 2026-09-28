"""
Authentication module for Xiaomi account.
Handles token-based authentication by accepting the user's service token directly.

Since Xiaomi has made 2FA mandatory and removed the option to disable it,
programmatic login via username/password is no longer possible.
Users must extract their session token from the browser manually.
"""

import json

import urllib3
from colorama import Fore, Style

from device import generate_device_id

TOKEN_MIN_LENGTH = 40  # new_bbs_serviceToken values are long base64-like strings
TOKEN_VERIFY_URL = "https://sgp-api.buy.mi.com/bbs/api/global/user/bl-switch/state"


def print_token_instructions() -> None:
    """Print step-by-step instructions for extracting the service token."""
    print(Style.BRIGHT + Fore.CYAN + "=" * 60)
    print("        How to get your serviceToken")
    print("=" * 60 + Style.RESET_ALL)
    print()
    print(Style.BRIGHT + "Xiaomi now requires 2FA on all accounts, so direct login")
    print("is no longer possible. You need to extract your session")
    print("token from the browser instead." + Style.RESET_ALL)
    print()
    print(Fore.YELLOW + "Method: Cookie Editor Extension (Recommended)" + Style.RESET_ALL)
    print()
    print("  1. Open " + Fore.CYAN + "Firefox" + Fore.RESET + " or " + Fore.CYAN + "Chrome" + Fore.RESET + " on your PC")
    print("  2. Install the " + Style.BRIGHT + "\"Cookie Editor\"" + Style.RESET_ALL + " extension:")
    print(Fore.BLUE + "     Firefox: https://addons.mozilla.org/addon/cookie-editor" + Fore.RESET)
    print(Fore.BLUE + "     Chrome:  https://chromewebstore.google.com/detail/cookie-editor/hlkenndednhfkekhgcdicdfddnkalmdm" + Fore.RESET)
    print("  3. Go to " + Fore.CYAN + "https://c.mi.com" + Fore.RESET + " and log in to your Xiaomi account")
    print("  4. Click the " + Style.BRIGHT + "Cookie Editor" + Style.RESET_ALL + " extension icon")
    print("  5. Search for " + Style.BRIGHT + Fore.GREEN + "new_bbs_serviceToken" + Style.RESET_ALL)
    print("  6. Copy the " + Style.BRIGHT + "Value" + Style.RESET_ALL + " field (long string of characters)")
    print("  7. Paste it below")
    print()
    print(Fore.YELLOW + "⚠️  Keep your token private — it grants access to your account." + Style.RESET_ALL)
    print()


def validate_token_format(token: str) -> bool:
    """
    Validate that the provided token looks reasonable based on format.

    Args:
        token: The token string to validate.

    Returns:
        bool: True if the token passes basic format validation.
    """
    if len(token) < TOKEN_MIN_LENGTH:
        return False

    # Token should only contain URL-safe characters (alphanumeric, +, /, =, %, etc.)
    allowed_extras = set("+/=%-_.")
    for char in token:
        if not (char.isalnum() or char in allowed_extras):
            return False

    return True


def verify_token_with_server(token: str) -> tuple[bool, str]:
    """
    Verify the token is valid by making a request to Xiaomi's API.

    Hits the bootloader unlock status endpoint to check if the session
    token is accepted by the server.

    Args:
        token: The service token to verify.

    Returns:
        tuple: (is_valid, message) where is_valid indicates if the token
               is accepted by the server, and message provides details.
    """
    device_id = generate_device_id()
    headers = {
        "Cookie": f"new_bbs_serviceToken={token};versionCode=500411;versionName=5.4.11;deviceId={device_id};"
    }

    try:
        http = urllib3.PoolManager(
            retries=False,
            timeout=urllib3.Timeout(connect=5.0, read=10.0)
        )
        response = http.request('GET', TOKEN_VERIFY_URL, headers=headers)
        response_data = json.loads(response.data.decode('utf-8'))
        code = response_data.get("code")

        if code == 100004:
            return False, "Token is expired or invalid. Please get a fresh token from your browser."
        elif code == 0:
            return True, "Token is valid — session authenticated."
        else:
            # Other codes (like application-specific states) still mean the token itself is valid
            return True, f"Token is valid (server response code: {code})."

    except urllib3.exceptions.HTTPError as e:
        return False, f"Network error while verifying token: {e}"
    except json.JSONDecodeError:
        return False, "Unexpected response from server while verifying token."
    except Exception as e:
        return False, f"Error verifying token: {e}"


def authenticate_user() -> str:
    """
    Authenticate user by accepting their service token directly.

    Prints instructions for how to extract the token from the browser,
    then prompts the user to paste it. Validates the token format and
    verifies it against Xiaomi's server before accepting.

    Returns:
        str: The service token for authenticated session.

    Raises:
        SystemExit: If the user cancels authentication.
    """
    print_token_instructions()

    while True:
        token = input(Style.BRIGHT + "Paste your serviceToken: " + Style.RESET_ALL).strip()

        if not token:
            print(Fore.YELLOW + "No token entered. Please try again.\n" + Fore.RESET)
            continue

        if not validate_token_format(token):
            print(Fore.RED + "❌ Invalid token format. The token should be a long string" + Fore.RESET)
            print(Fore.RED + "   (40+ characters) from the cookie value. Please try again.\n" + Fore.RESET)
            continue

        # Verify the token against Xiaomi's server
        print(Fore.CYAN + "🔍 Verifying token with Xiaomi servers..." + Fore.RESET)
        is_valid, message = verify_token_with_server(token)

        if not is_valid:
            print(Fore.RED + f"❌ {message}" + Fore.RESET)
            print(Fore.RED + "   Please try again with a valid token.\n" + Fore.RESET)
            continue

        print(Fore.GREEN + f"✅ {message}\n" + Fore.RESET)
        return token