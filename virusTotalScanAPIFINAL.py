import os
import sys
import time
import json
import hashlib
import argparse
import socket
from threading import BoundedSemaphore

try:
    import tkinter as tk
    from tkinter import filedialog
except ImportError:
    install_tkinter = input("Tkinter library is not installed. Do you want to install it? (Y/N): ")
    if install_tkinter.lower() in ['y', 'yes']:
        os.system('pip install tkinter')
        import tkinter as tk
        from tkinter import filedialog
    else:
        print("Tkinter library is required for file selection. Exiting...")
        exit(1)

try:
    import requests
except ImportError:
    install_requests = input("Requests library is not installed. Do you want to install it? (Y/N): ")
    if install_requests.lower() in ['y', 'yes']:
        os.system('pip install requests')
        import requests
    else:
        print("Requests library is required for making API requests. Exiting...")
        exit(1)

try:
    import concurrent.futures
    from concurrent.futures import ThreadPoolExecutor
except ImportError:
    install_concurrent = input("Concurrent library is not installed. Do you want to install it? (Y/N): ")
    if install_concurrent.lower() in ['y', 'yes']:
        os.system('pip install futures')
        import concurrent.futures
        from concurrent.futures import ThreadPoolExecutor
    else:
        print("Concurrent library is required for running tasks concurrently. Exiting...")
        exit(1)

try:
    from requests.exceptions import HTTPError
except ImportError:
    install_exceptions = input("Requests library is missing the 'exceptions' module. Do you want to install it? (Y/N): ")
    if install_exceptions.lower() in ['y', 'yes']:
        os.system('pip install requests')
        from requests.exceptions import HTTPError
    else:
        print("Requests library is missing the 'exceptions' module. Exiting...")
        exit(1)

try:
    import colorama
    from colorama import Fore, Style
except ImportError:
    install_colorama = input("Colorama library is not installed. Do you want to install it? (Y/N): ")
    if install_colorama.lower() in ['y', 'yes']:
        os.system('pip install colorama')
        import colorama
        from colorama import Fore, Style
    else:
        print("Colorama library is required for color formatting. Exiting...")
        exit(1)
        

MAX_WORKERS = 4
DELAY = 15
SEMAPHORE = BoundedSemaphore(MAX_WORKERS)
REQUESTS_MADE = 0
LAST_RESET = time.time()

# Initialize colorama
colorama.init()

# ANSI escape sequences for color
COLOR_RED = Fore.RED
COLOR_GREEN = Fore.GREEN
COLOR_RESET = Style.RESET_ALL

def get_headers(api_key):
    return {
        "x-apikey": api_key
    }

def select_files():
    print(f"{COLOR_GREEN}Opening file dialog...{COLOR_RESET}")
    root = tk.Tk()
    root.withdraw()
    file_paths = list(filedialog.askopenfilenames())

    if not file_paths:
        print(f"{COLOR_RED}No files selected.{COLOR_RESET}")
        return None

    print(f"{COLOR_GREEN}Selected files:{COLOR_RESET}", file_paths)
    return file_paths

def get_upload_url(api_key):
    fixed_text = "Getting special upload URL for large file..."
    print(f"{COLOR_GREEN}{fixed_text}{COLOR_RESET}")
    url = 'https://www.virustotal.com/api/v3/files/upload_url'
    headers = get_headers(api_key)
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    data = response.json()
    upload_url = data['data']
    print(f"{COLOR_GREEN}Received special upload URL:{COLOR_RESET}", upload_url)
    return upload_url

def upload_file(file_path, api_key):
    fixed_text = "Uploading file:"
    print(f"{COLOR_GREEN}{fixed_text}{COLOR_RESET}", file_path)
    upload_url = get_upload_url(api_key)
    headers = get_headers(api_key)

    try:
        with open(file_path, 'rb') as file:
            files = {
                'file': file
            }

            response = requests.post(upload_url, headers=headers, files=files)
            response.raise_for_status()

            data = response.json()

            file_id = data['data']['id']
            print(f"{COLOR_GREEN}File uploaded successfully. File ID:{COLOR_RESET}", file_id)
            return file_id
    except HTTPError as err:
        print(f'{COLOR_RED}HTTP error occurred: {err}{COLOR_RESET}')
    except Exception as err:
        print(f'{COLOR_RED}Other error occurred: {err}{COLOR_RESET}')

def get_existing_report(file_path, api_key):
    fixed_text = "Checking if results exist for: "
    print(f"{COLOR_GREEN}{fixed_text}{COLOR_RESET}", file_path)
    hash_value = calculate_file_hash(file_path)

    url = f'https://www.virustotal.com/api/v3/files/{hash_value}'
    headers = get_headers(api_key)

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            scan_results = data['data']['attributes']['last_analysis_results']
            fixed_text = "Results found for: "
            print(f"{COLOR_GREEN}{fixed_text}{COLOR_RESET}", file_path)
            return scan_results
        elif response.status_code == 404:
            fixed_text = "No results found for: "
            print(f"{COLOR_GREEN}{fixed_text}{COLOR_RESET}", file_path)
        else:
            print(f"{COLOR_RED}Error occurred while checking results for {file_path}: {response.status_code} {response.text}{COLOR_RESET}")
    except requests.exceptions.RequestException as err:
        print(f'{COLOR_RED}Error occurred while checking results for {file_path}: {err}{COLOR_RESET}')

    return None

def calculate_file_hash(file_path):
    BLOCK_SIZE = 65536  # Read file in chunks of 64KB
    hash_algorithm = hashlib.sha256()

    with open(file_path, 'rb') as file:
        buffer = file.read(BLOCK_SIZE)
        while len(buffer) > 0:
            hash_algorithm.update(buffer)
            buffer = file.read(BLOCK_SIZE)

    return hash_algorithm.hexdigest()

def retrieve_report(file_id, api_key, file_path):
    fixed_text = "Retrieving report for File ID:"
    print(f"{COLOR_GREEN}{fixed_text}{COLOR_RESET}", file_id)
    url = f'https://www.virustotal.com/api/v3/analyses/{file_id}'
    headers = get_headers(api_key)

    while True:
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()

            data = response.json()

            scan_results = data['data']['attributes']['results']
            scan_status = data['data']['attributes']['status']
            if scan_status == 'completed':
                print(f"{COLOR_GREEN}Scan completed for File ID:{COLOR_RESET}", file_id)
                return scan_results
            else:
                print(f'Scan not completed yet for {file_path}. Waiting...')
                time.sleep(10)
        except HTTPError as err:
            print(f'{COLOR_RED}HTTP error occurred: {err}{COLOR_RESET}')
            break
        except Exception as err:
            print(f'{COLOR_RED}Other error occurred: {err}{COLOR_RESET}')
            break

    return None

def save_results(file_path, scan_results):
    results_file_path = os.path.splitext(file_path)[0] + '_results.txt'
    print(f"{COLOR_GREEN}Saving results to:{COLOR_RESET}", results_file_path)

    with open(results_file_path, 'w') as file:
        json.dump(scan_results, file, indent=4)

def scan_file(file_path, api_key):
    if not os.path.isfile(file_path):
        print(f'{COLOR_RED}File does not exist:{COLOR_RESET}', file_path)
        return

    start_time = time.time()

    headers = get_headers(api_key)

    existing_report = get_existing_report(file_path, api_key)
    if existing_report:
        fixed_text = "Results already exist for: "
        print(f"{COLOR_GREEN}{fixed_text}{COLOR_RESET}", file_path)
        save_results(file_path, existing_report)
        results_file_path = os.path.splitext(file_path)[0] + '_results.txt'  # Define results_file_path here
        post_analysis(results_file_path)
    else:
        file_id = upload_file(file_path, api_key)
        if not file_id:
            return

        scan_results = retrieve_report(file_id, api_key, file_path)
        if not scan_results:
            return

        print(f"{COLOR_GREEN}Results for: {file_path}:{COLOR_RESET}")
        save_results(file_path, scan_results)
        results_file_path = os.path.splitext(file_path)[0] + '_results.txt'  # Define results_file_path here
        post_analysis(results_file_path)

    end_time = time.time()
    time_taken = end_time - start_time
    print(f"{COLOR_GREEN}Time taken for:{COLOR_RESET}", file_path, f"{COLOR_GREEN}{time_taken} seconds{COLOR_RESET}")

    SEMAPHORE.release()

def post_analysis(results_file_path):
    with open(results_file_path, 'r') as file:
        results = json.load(file)

    suspicious_files = []

    for engine, result in results.items():
        if result is not None and result['category'] == 'malicious':
            suspicious_files.append(engine)

    if suspicious_files:
        print(f"{COLOR_RED}Suspicious detection found in {results_file_path}{COLOR_RESET}")
        print("Engines detecting the file as suspicious:")
        for engine in suspicious_files:
            print(engine)
    else:
        file_name = os.path.basename(results_file_path)
        print(f"{COLOR_GREEN}No suspicious result in{COLOR_RESET} {file_name}")

    file.close()
    
def get_my_ip():
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    return ip_address

def get_remaining_requests(api_key, my_ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{my_ip}"
    headers = {
        "x-apikey": api_key
    }

    response = requests.get(url, headers=headers)
    data = response.json()

    # The exact key might vary, refer to the API documentation for the exact keys
    if 'data' in data and 'attributes' in data['data'] and 'requests_left' in data['data']['attributes']:
        return data['data']['attributes']['requests_left']
    else:
        return "Unable to fetch remaining requests."

def main(api_key, scan_type):
    
    global REQUESTS_MADE
    global LAST_RESET

    # Check if it has been more than an hour since the last reset
    if time.time() - LAST_RESET > 3600:
        # Reset the counter and the timer
        REQUESTS_MADE = 0
        LAST_RESET = time.time()

    # Check if the request limit has been reached
    if REQUESTS_MADE >= 240:
        print("Hourly request limit reached. Please wait for an hour before making more requests.")
        return

    # Increment the request counter
    REQUESTS_MADE += 1
    
    if scan_type == 1:
        # Code for scanning files
        file_paths = select_files()
        if not file_paths:
            return

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            for file_path in file_paths:
                SEMAPHORE.acquire()
                executor.submit(scan_file, file_path, api_key)
                time.sleep(DELAY)

        print(f"{COLOR_GREEN}Results files scanned: {len(file_paths)}{COLOR_RESET}")

    elif scan_type == 2:
        # Code for scanning results files
        file_paths = select_files()
        if not file_paths:
            return

        results_files_scanned = 0
        suspicious_results_files = []

        for file_path in file_paths:
            if "results.txt" in file_path:
                results_files_scanned += 1
                post_analysis(file_path)
                with open(file_path, 'r') as file:
                    results = json.load(file)
                if any(result is not None and result['category'] == 'malicious' for result in results.values()):
                    suspicious_results_files.append(file_path)

        if results_files_scanned > 0:
            print(f"{COLOR_GREEN}Results files scanned: {results_files_scanned}{COLOR_RESET}")
            if len(suspicious_results_files) > 0:
                print(f"{COLOR_RED}Suspicious detection found in the following results files:{COLOR_RESET}")
                for file_path in suspicious_results_files:
                    print(file_path)
            else:
                print(f"{COLOR_GREEN}No suspicious results files{COLOR_RESET}")
        else:
            print(f"{COLOR_RED}No results files found for scanning.{COLOR_RESET}")
            
    elif scan_type == 3:
            url = "https://www.virustotal.com/api/v3/users/41502ae28c93d30a0d3e139abbc783766712be4314b5e101b4e5a5a7f27f68e8/overall_quotas"

            headers = {
                "accept": "application/json",
                "x-apikey": "41502ae28c93d30a0d3e139abbc783766712be4314b5e101b4e5a5a7f27f68e8"
            }

            response = requests.get(url, headers=headers)

            print(response.text)
    else:
        print("Invalid scan tyape argument.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="VirusTotal Scan API")
    parser.add_argument('-t', '--type', type=int, default=1, help="Scan type (1: Scan files, 2: Scan results files, 3: API calls left)")
    args = parser.parse_args()

    api_key = '41502ae28c93d30a0d3e139abbc783766712be4314b5e101b4e5a5a7f27f68e8'
    if not api_key:
        print('API key not found. Set the API_KEY environment variable.')
        sys.exit(1)

    main(api_key, args.type)
