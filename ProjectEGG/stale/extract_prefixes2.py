import os
import json
import re

def find_prefix_file():
    for json_list in os.listdir('.'):
        if json_list.endswith('.json'):
            with open(json_list, 'r', encoding='utf-8', errors='ignore') as json_file:
                lines = json_file.readlines()
                if len(lines) >= 3 and "egg" in lines[2]:
                    return json_list

def extract_and_save_from_file(content):
    print("Converting...")
    try:
        bin_regex = re.compile(r'[a-zA-Z]{3}(\d{4}a)\.bin')

        # Split the content into lines based on commas
        lines = content.split(',')

        # Extract, subtract pattern, deduplicate, and sort matching strings
        matching_strings = sorted(
            set(re.sub(r'\d{4}a\.bin', '', match.group()) for line in lines for match in bin_regex.finditer(line))
        )

        with open('com.txt', 'w') as file:
            file.write('\n'.join(matching_strings))
            print("Saved as com.txt.")

    except Exception as e:
        print(f"Error during conversion: {e}")
        raise

prefix_file = find_prefix_file()
with open(prefix_file, 'r', encoding='utf-8', errors='ignore') as file:
    json_content = file.read()

extract_and_save_from_file(json_content)
