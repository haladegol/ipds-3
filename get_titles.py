import os, re
base_dir = r"c:\Users\asus\Downloads\hades2\templates"
titles = set()
for root, dirs, files in os.walk(base_dir):
    for f in files:
        if f.endswith(".html"):
            path = os.path.join(root, f)
            with open(path, "r", encoding="utf-8") as file:
                content = file.read()
                matches = re.findall(r'<div class="chart-header">.*?<h3>(.*?)</h3>', content, re.DOTALL)
                for m in matches:
                    title = re.sub(r'<[^>]+>', '', m).strip()
                    titles.add(title)

for t in sorted(titles):
    print("TITLE:", t)
