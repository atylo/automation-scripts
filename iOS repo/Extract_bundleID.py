import os
import zipfile
import plistlib
import shutil

def get_single_bundle_id(file_path):
    try:
        assert(zipfile.is_zipfile(file_path))
    except AssertionError:
        print(f"[!] bad zipfile: {os.path.basename(file_path)} ({file_path})")
        return None

    with zipfile.ZipFile(file_path) as archive:
        for file_name in (nl := archive.namelist()):
            if file_name.endswith(".app/Info.plist"):
                info_file = file_name
                break

        with archive.open(info_file) as fp:
            pl = plistlib.load(fp)
            bundleId = pl["CFBundleIdentifier"]

    return {"bundle": bundleId}

def extract_bundle_identifier(ipa_path, output_file):
    try:
        # Use the modified function to get the bundle identifier
        bundle_info = get_single_bundle_id(ipa_path)

        if bundle_info:
            bundle_identifier = bundle_info['bundle']
            # Write the bundle identifier to the output file
            output_file.write(f"{os.path.basename(ipa_path)}: {bundle_identifier}\n")
            print(f"{os.path.basename(ipa_path)}: {bundle_identifier}")

    except Exception as e:
        print(f"Error processing {ipa_path}: {e}")

def process_ipa_files(ipa_folder):
    output_file_path = 'bundle_identifiers.txt'

    with open(output_file_path, 'w') as output_file:
        for ipa_file in os.listdir(ipa_folder):
            if ipa_file.endswith('.ipa'):
                ipa_path = os.path.join(ipa_folder, ipa_file)
                extract_bundle_identifier(ipa_path, output_file)

# Replace 'YourIPAFolder' with the path to the folder containing your IPA files
ipa_folder_path = 'IPAs'
process_ipa_files(ipa_folder_path)
