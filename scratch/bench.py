import pandas as pd, time
from models.ml.pipeline import HADESPipeline

pipe = HADESPipeline()
df = pd.read_csv('uploads/3_20260430_005735_Batch_Dataset_10_files.csv', low_memory=False)
print(f'Loaded {len(df)} rows')
t0 = time.time()
res = pipe.analyze(df)
t1 = time.time()
print(f'Analysis done in {t1-t0:.2f}s')
pf = res['per_flow']
print(f'Per flow count: {len(pf)}')
if pf:
    print(f'First flow: {pf[0]}')
