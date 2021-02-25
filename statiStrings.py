"""
Author: Shelly Raban
Date: February 2021

* This script helps determine the prevalence of each string within a YARA rule in a directory of files 
* This script accepts rules which their strings section is structured in the following format:
* Each row contains: $<name> =
* with one space between the string name and the '=', for example:
$stringname = "string"
$hex_string = { 6b e? }
* It prints the results to the screen
* Example usage:
* Write a YARA rule that detects ransomware.
* Create a directory of hundreds of ransomware samples, and a directory of clean files.
* Run this script on both the ransomware and the clean directory, with the YARA rule you wrote.
* Use the results to understand the common characteristics of ransomware and potential false positives of your rule.
* Improve your Research and your YARA rule based on the results
* I recommend to start with a condition of "any of them" in combination with file header and file size, and make it more specific according to the results of statiStrings
"""

# Imports
import os
import yara
import re
import argparse
import os
import sys

# Constants
YARA_STRING_NAME_REGEX = r"(\$.*)\s="
SUM = 's'

# Functions
def get_script_path():
    return os.path.dirname(os.path.realpath(sys.argv[0]))

def welcome():
    banner_file = open(r"{}".format(os.path.join(get_script_path(),"cli_banner.txt")))
    ascii_banner = banner_file.read()

    print("{}\n{}\n".format(ascii_banner, "YARA Rule Strings Statistics Calculator\nShelly Raban (Sh3llyR), February 2021, Version 0.1\n"))

def parse_args():
    
    # Get Arguements From the User
    parser = argparse.ArgumentParser(description="YARA Rule Strings Statistics Calculator and Malware Research Helper")
    parser.add_argument('-y', dest='yara_rule', help='Path to the YARA Rule')
    parser.add_argument('-d', dest='test_dir', help='Path to the Directory of Files to be Scanned')
    parser.add_argument('-t', dest='output_type', help='Output Type: s (sum - number of files in which each string from the YARA rule ocuured) / p (percentage - percent of files in which each string from the YARA rule ocuured). Default is s', default=SUM)

    # Parse the Arguements
    args = parser.parse_args()
    
    # Return Args
    return args

def extract_rule_strings(yara_rule):
    
    # Extract Strings From Rule
    with open(yara_rule,'r') as rule:
        content = rule.read()
    rule_strings = list(set(re.findall(YARA_STRING_NAME_REGEX,content)))

    # Return the List of Strings
    return rule_strings

def compile_rule(yara_rule):
    
    # Compile Rule
    rule = yara.compile(yara_rule)

    # Return The Compiled Rule
    return rule

def calculate_string_occurances(compiled_rule, rule_strings, test_dir, output_type):
    
    # Create Dict of Matches
    files_scanned = {}

    # Scan Files Dir Againt The Loaded Yara Rule
    for root,d_names,f_names in os.walk(test_dir):
        for f in f_names:
            fpath = os.path.join(root, f)
            files_scanned[fpath] = compiled_rule.match(fpath)

    # Get Matched Strings
    # Count Occurances of Each String of The Rule in Files Dir

    strings_count = {}
    for string in rule_strings:
        strings_count[string] = 0

    for fpath in files_scanned:
        current_file_matches = []
        try:
            for string in files_scanned[fpath][0].strings:
                if string[1] not in current_file_matches:
                    current_file_matches.append(string[1])
                    strings_count[string[1]] += 1
        except:
            pass

    num_scanned_files = len(files_scanned)

    if output_type == 'p':
        for key in strings_count.keys():
            strings_count[key] = "{}%".format(str(int(strings_count[key] / num_scanned_files * 100)))

    return strings_count, num_scanned_files

def print_results(strings_count, num_scanned_files):

    print(strings_count)
        
    print("Number of files scanned: {}".format(str(num_scanned_files)))
    

# Main
if __name__ == '__main__':
    
    # Print welcome message
    welcome()
    
    # Parse Arguments
    args = parse_args()
    yara_rule = args.yara_rule
    test_dir = args.test_dir
    output_type = args.output_type

    # Show Only The Error Message When an Exception Occurs
    sys.tracebacklimit = 0

    # Extract Strings From Rule
    rule_strings = extract_rule_strings(yara_rule)

    # Compile Rule
    compiled_rule = compile_rule(yara_rule)

    # Calculate String Occurances
    strings_count, num_scanned_files = calculate_string_occurances(compiled_rule, rule_strings, test_dir, output_type)

    # Print Results
    print_results(strings_count, num_scanned_files)
