import re

def extract_ipa_links(text):
    pattern = r'\bhttps?://[^\s]+\.ipa\b'
    return re.findall(pattern, text)

def save_links_to_file(links, output_file='ipa_links.txt'):
    with open(output_file, 'w') as file:
        for link in links:
            file.write(link + '\n')

if __name__ == "__main__":
    # Specify the input and output file names
    input_file = 'repo.json'
    output_file = 'ipa_links.txt'

    try:
        # Read links from the input file
        with open(input_file, 'r') as input_file_handle:
            input_text = input_file_handle.read()

        # Extract links using the regex pattern
        ipa_links = extract_ipa_links(input_text)

        # Save the IPA links to a text file
        save_links_to_file(ipa_links, output_file)

        print(f"IPA links from '{input_file}' saved to '{output_file}'")
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")