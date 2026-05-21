import os, re

base_dir = r"c:\Users\asus\Downloads\hades2"
templates_dir = os.path.join(base_dir, "templates")
static_dir = os.path.join(base_dir, "static")

# 1. Update text globally in all templates
for root, dirs, files in os.walk(templates_dir):
    for f in files:
        if f.endswith(".html"):
            path = os.path.join(root, f)
            with open(path, "r", encoding="utf-8") as file:
                content = file.read()
            
            orig_content = content
            # Rename HADES IDS / IPS to IDPS
            content = re.sub(r'HADES IDS', 'HADES IDPS', content)
            content = re.sub(r'HADES IPS', 'HADES IDPS', content)
            content = re.sub(r'Intrusion Detection System', 'Intrusion Detection and Prevention System', content, flags=re.IGNORECASE)
            content = re.sub(r'Intrusion Prevention System', 'Intrusion Detection and Prevention System', content, flags=re.IGNORECASE)
            
            # 2. Append explanation button to charts
            # <div class="chart-header">\s*<h3>(.*?)</h3>
            # We want to insert the button next to the h3
            
            def chart_header_replacer(match):
                full_match = match.group(0)
                # If we've already added it, skip
                if "info-btn" in full_match or "chart-info-panel" in full_match:
                    return full_match
                
                header_content = match.group(1) # everything inside chart-header
                
                # Extract the title if possible
                title_match = re.search(r'<h3>(.*?)</h3>', header_content)
                title = title_match.group(1) if title_match else "this data"
                # Strip out HTML tags from title like <span>
                title = re.sub(r'<[^>]+>', '', title)
                
                explanation = f"This chart visualizes {title.lower()} to monitor network security. Use this data to identify anomalous patterns and respond to threats efficiently within the HADES IDPS ecosystem."
                
                # Wrap h3 in a flex container if it's not already
                if "<h3>" in header_content:
                    new_h3 = f'''<div style="display: flex; align-items: center; gap: 10px;">
                {title_match.group(0)}
                <button type="button" class="info-btn" onclick="let p = this.closest('.chart-card').querySelector('.chart-info-panel'); p.style.display = p.style.display === 'none' ? 'block' : 'none';" title="View Explanation">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
                </button>
            </div>'''
                    new_header_content = header_content.replace(title_match.group(0), new_h3)
                else:
                    new_header_content = header_content
                
                new_block = f'''<div class="chart-header">
{new_header_content}
</div>
<div class="chart-info-panel" style="display: none; padding: 12px 20px; font-size: 0.88em; color: var(--text-muted); background: rgba(64,138,113,0.08); border-bottom: 1px solid rgba(64,138,113,0.15); line-height: 1.5; border-radius: 0 0 8px 8px; margin-bottom: 8px;">
    <strong>Explanation:</strong> {explanation}
</div>'''
                return new_block
            
            content = re.sub(r'<div class="chart-header">(?!\s*<div style="display: flex)(.*?)</div>', chart_header_replacer, content, flags=re.DOTALL)
            
            # Make charts more readable by changing chart defaults
            # '8fb8a8' -> '#e2e8f0' for better contrast
            content = content.replace("Chart.defaults.color = '#8fb8a8'", "Chart.defaults.color = '#e2e8f0'")
            content = content.replace("Chart.defaults.color='#8fb8a8'", "Chart.defaults.color='#e2e8f0'")
            content = content.replace("color: '#8fb8a8'", "color: '#e2e8f0'")
            content = content.replace("color:'#8fb8a8'", "color:'#e2e8f0'")
            
            if content != orig_content:
                with open(path, "w", encoding="utf-8") as file:
                    file.write(content)

# Add css for .info-btn
css_path = os.path.join(static_dir, "css", "style.css")
with open(css_path, "r", encoding="utf-8") as f:
    css_content = f.read()

if ".info-btn {" not in css_content:
    css_add = """
/* Chart Info Button */
.info-btn {
    background: transparent;
    border: none;
    color: var(--green-bright);
    cursor: pointer;
    opacity: 0.6;
    transition: all 0.2s ease;
    padding: 0;
    display: flex;
    align-items: center;
    justify-content: center;
}
.info-btn:hover {
    opacity: 1;
    color: var(--green-light);
    transform: scale(1.1);
}
"""
    with open(css_path, "a", encoding="utf-8") as f:
        f.write(css_add)

print("Done updating templates for IDPS, chart readability, and explanation toggles.")
