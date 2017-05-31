# File Forensics

Analyze all files in specified directory (non deleted) and applies multiple
checks to find out if any of them could be worth further investigation:

  - check if file signature **miss matches file extension** (in progress)
  - match file **contents against set of keywords** (eg. "confidential", "password", by default only first 1mb of file is checked)
  - flag files with **high entropy** (potentially cryptographic material, compressed)
  - identify any **big files** (by default files larger than 10mb)

# How to use

## Requirements

  - python 2.7+ (not platform specific -- Linux, MacOs, Windows)

## Installation

Installation requires downloading additional libraries using Python package manager (pip)

```
pip install -r requirements.txt
```

## Configuration

Create file called "keywords" with one keyword per line (case sensitive) -- these keywords will be matched against every file using efficient AC algorithm (by default only first 1mb of file is checked).

## Run

```
python file_forensics.py /path/to/directory/
```

As output you should receive text containing flag type and name of file plus some useful information about file:

```
--- BIG FILES ---
      1845 MB   application/x-7z-compressed /full/path/archive.7z
        68 MB   video/quicktime      /full/path/video.mov

--- FOUND KEYWORDS ---
2     text/plain           (/full/path/ga.js)
        - uest;if(!c)return!1;var d=new c;if(!("withCredentials"in d))return!1;d.open("POST",Ne()+"/p/__utm.gif Credential
        - open("POST",Ne()+"/p/__utm.gif",!0);d.withCredentials=!0;d.setRequestHeader("Content-Type","text/plai Credential

--- HIGH ENTROPY FILES ---
        0.82 (application/octet-stream) /full/path/file.pxm
```
