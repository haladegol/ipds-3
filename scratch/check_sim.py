with open('routes/simulation.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()
    src = ''.join(lines)

issues = []

for i, line in enumerate(lines, 1):
    s = line.rstrip()

    # 1. Unused import: os
    if s.strip() == 'import os':
        issues.append((i, 'UNUSED IMPORT', 'os is imported but never referenced in this file'))

    # 2. Unused import: datetime
    if 'from datetime import datetime' in s:
        issues.append((i, 'UNUSED IMPORT', 'datetime is imported but never called anywhere'))

    # 3. Unused import: jsonify
    if 'jsonify' in s and 'import' in s:
        issues.append((i, 'UNUSED IMPORT', 'jsonify is imported but no route returns a JSON response'))

    # 4. Unused variable: missed
    if 'missed = flow_count - detected' in s:
        issues.append((i, 'UNUSED VAR', "'missed' is assigned but never used — dead assignment"))

    # 5. Scope risk: elapsed
    if 'elapsed = round(time.time() - start_time, 3)' in s and i > 325:
        issues.append((i, 'SCOPE RISK', "'elapsed' defined only inside inner try block — if real pipeline crashes before this line, outer except references undefined 'elapsed'"))

    # 6. Dead code: grade (confidence scoring removed from UI)
    if 'analytics["grade"] = grade' in s:
        issues.append((i, 'DEAD CODE', "'grade' dict computed and stored but template grade display was entirely removed — wasted computation"))

    # 7. Dead code: detection_methods (chart removed)
    if 'analytics["detection_methods"]' in s and '=' in s:
        issues.append((i, 'DEAD CODE', "'detection_methods' stored in analytics but the Detection Engine Split chart was removed from the template"))

    # 8. Dead code: key_features (chart removed)
    if 'analytics["key_features"] = key_features' in s:
        issues.append((i, 'DEAD CODE', "'key_features' computed per-profile and stored but the Synthetic Feature Ranges section was removed from the template"))

    # 9. Dead code: confidence_stats (confidence purged from UI)
    if 'analytics["confidence_stats"]' in s and '=' in s:
        issues.append((i, 'DEAD CODE', "'confidence_stats' stored but confidence metrics were entirely purged from the simulation UI"))

    # 10. Dead local var: confidence_values (feeds dead confidence_stats)
    if 'confidence_values = []' in s:
        issues.append((i, 'DEAD CODE', "'confidence_values' accumulated in loop but only feeds the dead 'confidence_stats' block — entire branch is dead"))

print(f"{'Line':>5}  {'Type':<20} Description")
print('-' * 90)
for lineno, kind, msg in sorted(issues):
    print(f"  {lineno:>3}  [{kind:<18}] {msg}")
print()
print(f"Total issues found: {len(issues)}")
