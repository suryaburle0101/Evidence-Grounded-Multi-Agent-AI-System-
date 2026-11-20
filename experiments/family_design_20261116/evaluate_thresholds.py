"""Sensitivity run for the primary family model at a 0.5% calibration target."""
from __future__ import annotations
import json
from pathlib import Path
import numpy as np
import pandas as pd
from evaluate_families import ROOT,OUT,BASE,SEEDS,FEATURES,project,read_seed,choose_calibration,remove_test_duplicates,fit_predict

def main():
    cfg=json.loads((OUT/'families.json').read_text(encoding='utf-8'))['primary_5_family_mapping']
    rows=[]; famrows=[]
    for seed in SEEDS:
        frames=read_seed(seed)
        for f in frames.values(): f['__target']=f['__type'].map(cfg)
        names=list(frames)
        for heldout in names:
            cals=choose_calibration(frames,heldout)
            train_names=[n for n in names if n not in {heldout,*cals}]
            train=pd.concat([frames[n] for n in train_names],ignore_index=True)
            cal=pd.concat([frames[n].loc[frames[n]['__type'].eq('Benign')] for n in cals],ignore_index=True)
            test=frames[heldout]
            train,removed=remove_test_duplicates(train,test,'__target')
            score,pred,p,classes,threshold,details=fit_predict(train,cal,test,seed,.005)
            y=test['__target'].to_numpy(); attack=y!='Benign'; fire=score>=threshold
            benign=~attack
            rows.append({'seed':seed,'heldout_capture':heldout,'threshold_target_fpr':.005,
                'threshold':threshold,'threshold_calibration':json.dumps(details),
                'attack_rows':int(attack.sum()),'benign_rows':int(benign.sum()),
                'attack_recall':float(fire[attack].mean()) if attack.any() else np.nan,
                'capture_fpr':float(fire[benign].mean()) if benign.any() else np.nan,
                'false_positive_rows':int((fire&benign).sum()),'train_test_duplicate_vectors_removed':removed,
                'pr_auc_attack':float(__import__('sklearn.metrics',fromlist=['average_precision_score']).average_precision_score(attack.astype(int),score)) if attack.any() and benign.any() else np.nan})
            for family in [c for c in classes if c!='Benign']:
                mask=y==family
                famrows.append({'seed':seed,'heldout_capture':heldout,'family':family,'support':int(mask.sum()),
                    'correct_family_recall':float(((pred[mask]==family)&fire[mask]).mean()) if mask.any() else np.nan})
        print(f'Completed 0.5% threshold seed {seed}',flush=True)
    d=pd.DataFrame(rows); d.to_csv(OUT/'family_threshold_0_5_capture_metrics.csv',index=False)
    pd.DataFrame(famrows).to_csv(OUT/'family_threshold_0_5_per_family.csv',index=False)
    summaries=[]
    one=pd.read_csv(OUT/'family_capture_metrics_3seeds.csv'); one=one[one.variant.eq('primary_5')]
    for seed in SEEDS:
        for label,frame in [('1.0%',one[one.seed.eq(seed)]),('0.5%',d[d.seed.eq(seed)])]:
            fp=int(frame.false_positive_rows.sum()) if 'false_positive_rows' in frame else int((frame.capture_fpr*frame.benign_rows).fillna(0).round().sum())
            bn=int(frame.benign_rows.sum())
            summaries.append({'seed':seed,'target':label,'attack_recall':float(frame.attack_recall.mean()),
                'mean_capture_fpr':float(frame.capture_fpr.mean()),'pooled_fpr':fp/bn if bn else np.nan,
                'worst_capture_fpr':float(frame.capture_fpr.max()),'mean_pr_auc':float((frame.attack_pr_auc if 'attack_pr_auc' in frame else frame.pr_auc_attack).mean())})
    z=pd.DataFrame(summaries); z.to_csv(OUT/'family_threshold_comparison_seed.csv',index=False)
    roll=z.groupby('target').agg(attack_recall_mean=('attack_recall','mean'),attack_recall_sd=('attack_recall','std'),
        mean_capture_fpr=('mean_capture_fpr','mean'),pooled_fpr=('pooled_fpr','mean'),
        worst_capture_fpr=('worst_capture_fpr','max'),mean_pr_auc=('mean_pr_auc','mean')).reset_index()
    roll.to_csv(OUT/'family_threshold_comparison.csv',index=False)
    print(roll.to_string(index=False))

if __name__=='__main__': main()
