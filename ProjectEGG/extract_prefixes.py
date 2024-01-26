import re
import codecs

input_file_path = 'com list.txt'
output_file_path = 'com.txt'

with codecs.open(input_file_path, 'r', encoding='utf-8', errors='replace') as file, open(output_file_path, 'w') as output_file:
    for line in file:
        match = re.search(r'\b(?<!\S)([A-Z]{3})(?!\S)\b', line)
        if match:
            output_file.write(match.group(1) + '\n')
