from colorama import Fore, Style
from tqdm import tqdm
import requests
import time

print(Fore.GREEN + "✅ Environment is working!" + Style.RESET_ALL)

for _ in tqdm(range(5), desc="Testing progress bar"):
    time.sleep(0.5)

try:
    response = requests.get("https://example.com", timeout=5)
    print(Fore.CYAN + f"HTTP test successful: {response.status_code}" + Style.RESET_ALL)
except Exception as e:
    print(Fore.RED + f"HTTP test failed: {e}" + Style.RESET_ALL)
