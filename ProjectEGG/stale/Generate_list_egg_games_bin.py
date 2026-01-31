import os
import json
import re
import requests

USER_AGENT = 'c384da2W9f73dz20403d'
username = 'lolcat54'
password = 'lostmypass'

def get_response(username, password):
    print("Downloading...")
    try:
        response = requests.post(
            'https://api.amusement-center.com/api/dcp/v1/getcontentslist',
            headers={'User-Agent': USER_AGENT},
            data={'userid': username, 'passwd': password}
        )
        verify=False
        response.raise_for_status()  # Raise an exception for bad responses (non-2xx status codes)

        return response

    except requests.RequestException as e:
        print(f"Error during download: {e}")
        raise

def find_prefix_file():
    # Check if "com.txt" exists
    if os.path.exists('com.txt'):
        return 'com.txt', 1
    
    # Search for any JSON file and check for "egg" on the third line
    for json_list in os.listdir('.'):
        if json_list.endswith('.json'):
            with open(json_list, 'r', encoding='utf-8', errors='ignore') as json_file:
                lines = json_file.readlines()
                if len(lines) >= 3 and "egg" in lines[2]:
                    return json_list, 2

    return None  # Return None if no suitable file is found

def extract_and_save_from_file(content):
    print("Converting...")
    try:
        bin_regex = re.compile(r'([a-zA-Z]{3}\d{4}a\.bin|P[a-zA-Z]{3}\d{4}a\.bin)')

        # Split the content into lines based on commas
        lines = content.split(',')

        matching_strings = sorted(
            {match.group() for line in lines for match in bin_regex.finditer(line)}
        )

        with open('bins_list.txt', 'w') as file:
            file.write('\n'.join(matching_strings))
            print("Saved as bins_list.txt.")

    except Exception as e:
        print(f"Error during conversion: {e}")
        raise


def generate_names(prefix_file):
    print("Using coms to generate a long list...")
    if prefix_file is None:
        print("No suitable file found.")
        return []

    with open(prefix_file, 'r', encoding='utf-8', errors='ignore') as file:
        lines = file.read().splitlines()

    names = []
    
    for line in lines:
        prefix = line.strip().upper()  # Extract prefix and convert to uppercase

        # Determine ranges based on prefix
        first_num_range = range(10) if prefix == "COM" else \
                          [0, 1, 3] if prefix in {"BOT", "SKP"} else \
                          range(4) if prefix == "TEL" else \
                          [0, 1]
        second_num_range = [0, 1] if prefix in {"FAL", "COM"} else [0]

        # Generate names
        for first_num in first_num_range:
            for second_num in second_num_range:
                for third_fourth_num in range(100):
                    third_num = third_fourth_num // 10
                    fourth_num = third_fourth_num % 10
                    name = f"{prefix}{first_num}{second_num}{third_num}{fourth_num}a.bin"
                    names.append(name)

    return names



# Code Start
prefix_file_result = find_prefix_file()

if prefix_file_result is not None:
    prefix_file, type = prefix_file_result
    if type == 1:
        # If it's not a JSON file, run generate_names() function
        name_list = generate_names(prefix_file)
        with open('bins_list.txt', 'w') as file:
            file.write('\n'.join(name_list))
            print("Saved as bins_list.txt.")
    elif type == 2:
        # If a JSON file is found, extract and save matching strings directly
        with open(prefix_file, 'r', encoding='utf-8', errors='ignore') as file:
            json_content = file.read()
        extract_and_save_from_file(json_content)
else:
    print("No suitable file found. Downloading the list and converting it.")
    response = get_response(username, password)
    extract_and_save_from_file(response.text)
