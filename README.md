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

## Requirements

- Python 3.x
- `requests` library
- `prettytable` library
- `tqdm` library

You can install the required libraries using pip:

```bash
pip install requests prettytable tqdm
