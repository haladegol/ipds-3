import urllib.request
import zipfile
import io
import sys

def download_and_extract(url, extract_to):
    print(f"Downloading {url}...")
    try:
        req = urllib.request.Request(
            url, 
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        )
        with urllib.request.urlopen(req) as response:
            zip_content = response.read()
        print("Download successful! Extracting...")
        with zipfile.ZipFile(io.BytesIO(zip_content)) as zip_ref:
            zip_ref.extractall(extract_to)
        print(f"Extracted successfully to {extract_to}")
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False

# Try main first, then master
url_main = "https://github.com/haladegol/ipds/archive/refs/heads/main.zip"
url_master = "https://github.com/haladegol/ipds/archive/refs/heads/master.zip"

if not download_and_extract(url_main, "tmp/repo_extracted"):
    print("Trying master branch...")
    download_and_extract(url_master, "tmp/repo_extracted")
