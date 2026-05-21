import os
import hashlib

def file_sha256(filepath):
    h = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        return f"error: {e}"

def get_all_files(root_dir):
    # Added 'uploads' to ignored dirs to exclude user uploaded CSV datasets
    ignored_dirs = {'.git', 'tmp', '__pycache__', 'scratch', 'venv', '.gemini', 'uploads'}
    file_map = {}
    for dirpath, dirnames, filenames in os.walk(root_dir):
        # Filter ignored directories in-place
        dirnames[:] = [d for d in dirnames if d not in ignored_dirs]
        for filename in filenames:
            abs_path = os.path.join(dirpath, filename)
            rel_path = os.path.relpath(abs_path, root_dir)
            # Normalize path separators
            rel_path = rel_path.replace('\\', '/')
            file_map[rel_path] = abs_path
    return file_map

local_dir = r"c:\Users\asus\Downloads\hades2"
repo_dir = r"c:\Users\asus\Downloads\hades2\tmp\repo_extracted\ipds-main"

local_files = get_all_files(local_dir)
repo_files = get_all_files(repo_dir)

missing_in_repo = []
missing_in_local = []
different_files = []
identical_files = []

for rel_path, local_abs in local_files.items():
    if rel_path not in repo_files:
        missing_in_repo.append(rel_path)
    else:
        repo_abs = repo_files[rel_path]
        local_hash = file_sha256(local_abs)
        repo_hash = file_sha256(repo_abs)
        
        # Also check file size
        local_size = os.path.getsize(local_abs)
        repo_size = os.path.getsize(repo_abs)
        
        if local_hash != repo_hash or local_size != repo_size:
            different_files.append((rel_path, local_size, repo_size))
        else:
            identical_files.append(rel_path)

for rel_path in repo_files:
    if rel_path not in local_files:
        missing_in_local.append(rel_path)

print("--- EXCLUSIVE TO LOCAL (MISSING IN GITHUB REPO) ---")
for f in sorted(missing_in_repo):
    size = os.path.getsize(local_files[f])
    print(f"- {f} ({size:,} bytes)")

print("\n--- EXCLUSIVE TO GITHUB REPO (MISSING IN LOCAL) ---")
for f in sorted(missing_in_local):
    size = os.path.getsize(repo_files[f])
    print(f"- {f} ({size:,} bytes)")

print("\n--- DIFFERENT FILES (PRESENT IN BOTH BUT MODIFIED/DIFFERENT) ---")
for f, l_sz, r_sz in sorted(different_files, key=lambda x: x[0]):
    print(f"- {f} (Local size: {l_sz:,} bytes | Repo size: {r_sz:,} bytes)")

print(f"\nSummary (excluding uploads/):")
print(f"Total local files indexed: {len(local_files)}")
print(f"Total repo files indexed: {len(repo_files)}")
print(f"Identical files in both: {len(identical_files)}")
print(f"Missing in repo: {len(missing_in_repo)}")
print(f"Missing in local: {len(missing_in_local)}")
print(f"Different/Modified: {len(different_files)}")
