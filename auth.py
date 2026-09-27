"""
Authentication module for Xiaomi account.
Handles token-based authentication by accepting the user's service token directly.

Since Xiaomi has made 2FA mandatory and removed the option to disable it,
programmatic login via username/password is no longer possible.
Users must extract their session token from the browser manually.
"""

from colorama import Fore, Style

TOKEN_MIN_LENGTH = 40  # new_bbs_serviceToken values are long base64-like strings


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


def validate_token(token: str) -> bool:
    """
    Validate that the provided token looks reasonable.

    Args:
        token: The token string to validate.

    Returns:
        bool: True if the token passes basic validation.
    """
    if len(token) < TOKEN_MIN_LENGTH:
        return False

    # Token should only contain URL-safe characters (alphanumeric, +, /, =, %, etc.)
    allowed_extras = set("+/=%-_.")
    for char in token:
        if not (char.isalnum() or char in allowed_extras):
            return False

    return True


def authenticate_user() -> str:
    """
    Authenticate user by accepting their service token directly.

    Prints instructions for how to extract the token from the browser,
    then prompts the user to paste it.

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

        if not validate_token(token):
            print(Fore.RED + "❌ Invalid token format. The token should be a long string" + Fore.RESET)
            print(Fore.RED + "   (40+ characters) from the cookie value. Please try again.\n" + Fore.RESET)
            continue

        print(Fore.GREEN + "✅ Token accepted.\n" + Fore.RESET)
        return token