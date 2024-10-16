<h1>EyeOnDirs</h1>

# Directory Enumerator Tool

A powerful directory enumeration tool designed to discover hidden directories and files on a web server. This tool uses multithreading to enhance performance and supports recursive searches and file extension filtering.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Examples](#examples)
- [License](#license)

## Features

- **Multithreading Support:** Speed up scans by utilizing multiple threads.
- **Recursive Searching:** Option to search directories recursively.
- **File Extension Filtering:** Specify file extensions to look for.
- **Sub-Domain Enumeration:** Option to discover sub-domains of a given URL.
- **Detailed Output:** Results displayed in a formatted table.
- **Usage Logging:** Log important events and errors.




## Parameters:
-url: The target URL or IP address (e.g., http://example.com).
-wordlist: Path to the wordlist file containing directories/files to check.
-t: Timeout for each request (default: 10 seconds).
-threads: Number of threads to use (default: 100).
--recursive or -r: Enables recursive directory searching.
-e or --extention: Comma-separated list of file extensions to look for.
-sd or --sub-domains: Enables sub-domain enumeration.


## Requirements

- Python 3.x
- `requests` library
- `prettytable` library
- `tqdm` library

You can install the required libraries using pip:

<code>pip install requests prettytable tqdm</code>

## Installation

To install the required libraries, run the following commands:

```bash
git clone https://github.com/yourusername/directory-enumerator.git
cd directory-enumerator
