# statiStrings
   ```sh
         _        _   _ ____  _        _
	 ___| |_ __ _| |_(_) ___|| |_ _ __(_)_ __   __ _ ___
	/ __| __/ _` | __| \___ \| __| '__| | '_ \ / _` / __|
	\__ \ || (_| | |_| |___) | |_| |  | | | | | (_| \__ \
	|___/\__\__,_|\__|_|____/ \__|_|  |_|_| |_|\__, |___/
			       			    |___/
	YARA Rule Strings Statistics Calculator
	Shelly Raban (Sh3llyR), February 2021, Version 0.1
   ```

<!-- PROJECT SHIELDS -->
<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
-->



<!-- TABLE OF CONTENTS -->
<details open="open">
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgements">Acknowledgements</a></li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## About The Project

statiStrings is a strings statistics calculator for YARA rules.

The goal is to aid malware research by:
* Finding common and unique strings within malware samples
* Finding common strings within clean files
* Saving time by finding the common characteristics of malware samples automatically

This tool helps writing better, more precise YARA rules for malware detection and malware hunting, based on custom databases of malicious and clean files.

For a given YARA rule and a directory of files, this tool returns the prevalence of each string from the rule in the matched files from the directory.



### Built With

* [Python](https://www.python.org/)



<!-- GETTING STARTED -->
## Getting Started

To use this tool, you must have Python installed.


### Installation

Install yara-python
   ```sh
   pip install yara
   ```

Clone the repo
   ```sh
   git clone https://github.com/Sh3llyR/statiStrings.git
   ```



<!-- USAGE EXAMPLES -->
## Usage

   ```sh
	usage: statiStrings.py [-h] [-y YARA_RULE] [-d TEST_DIR] [-t OUTPUT_TYPE]

	YARA Rule Strings Statistics Generator and Malware Research Helper

	optional arguments:
	  -h, --help      show this help message and exit
	  -y YARA_RULE    Path to the YARA Rule
	  -d TEST_DIR     Path to the Directory of Files to be Scanned
	  -t OUTPUT_TYPE  Output Type: s (sum - number of files in which each string
					  from the YARA rule ocuured) / p (percentage - percent of
					  files in which each string from the YARA rule ocuured).
					  Default is s
   ```

### Usage example

Research of common strings in malicious batch scripts:
First, I wrote a YARA rule with many commands that were found in malicious scripts. The condition was "any of them" - very generic.
Then, I ran this tool with the rule I wrote against a malicious scripts directory (shown in the following example).
Finally, I ran it against a directory with clean scripts.
After Going through the results of both clean and malicious scripts, I was able to:
1. Group the strings of the YARA rule to suspicios ($s_...), for example tskill, and noisy ($n_...), for example echo.
2. Create a condition for my rule that catches the malicious samples but not the clean samples, minimizing false positives.

* python statiStrings.py -y .\batch_commands.yar -d .\batch_samples -t s
* Results:
	```sh
	{'$s_ren': 1, '$n_set': 8, '$s_mem': 1, '$s_reg_add': 8, '$s_taskkill': 4, '$n_exit': 9, '$s_maybe_block_sites_hosts_file': 1, '$s_move': 2, '$s_attrib': 6, '$n_copy': 6, '$n_start': 10, '$n_type': 7, '$n_echo': 26, '$n_reg': 11, '$s_aes': 1, '$s_cscript': 1, '$s_change_mouse_settings': 1, '$n_net': 3, '$n_find': 6, '$s_infinite_loop': 2, '$s_shutdown': 9, '$n_del': 6, '$n_goto': 12, '$s_generic_bat_maybe_copy_itself': 5, '$n_ipconfig': 2, '$n_maybe_time_change': 5, '$n_system': 2, '$s_tskill': 3, '$s_cpu_damage': 1, '$s_erase': 3, '$s_make_random_folders': 1, '$s_sleep': 4, '$n_bat_maybe_copy_itself': 9}
	Number of files scanned: 157
	```
* python statiStrings.py -y .\batch_commands.yar -d .\batch_samples -t p
* Results:
	```sh
	{'$s_maybe_block_sites_hosts_file': '0.64%', '$s_sleep': '2.55%', '$s_shutdown': '5.73%', '$s_attrib': '3.82%', '$s_change_mouse_settings': '0.64%', '$n_maybe_time_change': '3.18%', '$s_erase': '1.91%', '$s_move': '1.27%', '$n_net': '1.91%', '$s_aes': '0.64%', '$n_reg': '7.01%', '$n_system': '1.27%', '$n_set': '5.1%', '$s_cscript': '0.64%', '$n_find': '3.82%', '$s_generic_bat_maybe_copy_itself': '3.18%', '$s_cpu_damage': '0.64%', '$n_goto': '7.64%', '$s_tskill': '1.91%', '$s_ren': '0.64%', '$s_mem': '0.64%', '$n_type': '4.46%', '$s_taskkill': '2.55%', '$n_exit': '5.73%', '$n_echo': '16.56%', '$s_infinite_loop': '1.27%', '$n_start': '6.37%', '$s_make_random_folders': '0.64%', '$n_bat_maybe_copy_itself': '5.73%', '$n_ipconfig': '1.27%', '$s_reg_add': '5.1%', '$n_del': '3.82%', '$n_copy': '3.82%'}
	Number of files scanned: 157
	```

<!-- CONTACT -->
## Contact

[![LinkedIn][linkedin-shield]][linkedin-url]

Project Link: [https://github.com/Sh3llyR/statiStrings](https://github.com/Sh3llyR/statiStrings)



<!-- ACKNOWLEDGEMENTS -->
## Acknowledgements
* [Img Shields](https://shields.io)



<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=555
[linkedin-url]: https://www.linkedin.com/in/shelly-raban-6baa2b1b9/
