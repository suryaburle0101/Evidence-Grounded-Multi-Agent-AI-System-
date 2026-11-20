"""Bidirectional CICIDS17/CSE-CIC-IDS2018 family transfer with source-only calibration."""
from __future__ import annotations
import json
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score
from evaluate_families import OUT,SEEDS,read_seed,remove_test_duplicates,fit_predict

def choose_source_calibration(source_frames):
    """Choose two source-only benign captures while preserving source family coverage."""
    eligible=[n for n,f in source_frames.items() if int(f['__type'].eq('Benign').sum())>=100]
    if len(eligible)<2: raise RuntimeError('Fewer than two source benign calibration captures')
    families=sorted(set().union(*(set(f.loc[f['__type'].ne('Benign'),'__target']) for f in source_frames.values())))
    best=None
    for i,a in enumerate(eligible):
        for b in eligible[i+1:]:
            remaining=[f for n,f in source_frames.items() if n not in {a,b}]
            available=set().union(*(set(f.loc[f['__type'].ne('Benign'),'__target']) for f in remaining))
            lost=len(set(families)-available)
            removed=sum(int(source_frames[n]['__target'].ne('Benign').sum()) for n in (a,b))
            key=(lost,removed,a,b)
            if best is None or key<best[0]: best=(key,(a,b))
    return list(best[1])

def main():
    cfg=json.loads((OUT/'families.json').read_text(encoding='utf-8'))['primary_5_family_mapping']
    caprows=[]; famrows=[]; calibrows=[]
    for seed in SEEDS:
        frames=read_seed(seed)
        for f in frames.values(): f['__target']=f['__type'].map(cfg)
        for source_dataset,target_dataset in [('CICIDS2017','CSE-CIC-IDS2018'),('CSE-CIC-IDS2018','CICIDS2017')]:
            source={n:f for n,f in frames.items() if f['__dataset'].iloc[0]==source_dataset}
            target={n:f for n,f in frames.items() if f['__dataset'].iloc[0]==target_dataset}
            cals=choose_source_calibration(source)
            train_names=[n for n in source if n not in cals]
            train=pd.concat([source[n] for n in train_names],ignore_index=True)
            cal=pd.concat([source[n].loc[source[n]['__type'].eq('Benign')] for n in cals],ignore_index=True)
            test_all=pd.concat(list(target.values()),ignore_index=True)
            train,removed=remove_test_duplicates(train,test_all,'__target')
            score,pred,p,classes,threshold,details=fit_predict(train,cal,test_all,seed,.01)
            family_classes=[c for c in classes if c!='Benign']
            for name,test in target.items():
                # Concatenation preserves order; calculate the exact offset block.
                start=sum(len(target[k]) for k in list(target)[:list(target).index(name)])
                ix=np.arange(start,start+len(test)); y=test['__target'].to_numpy(); attack=y!='Benign'; benign=~attack
                fire=score[ix]>=threshold; out=pred[ix]; pp=p[ix]
                caprows.append({'seed':seed,'train_dataset':source_dataset,'test_dataset':target_dataset,
                    'heldout_capture':name,'test_rows':len(test),'attack_rows':int(attack.sum()),'benign_rows':int(benign.sum()),
                    'attack_recall':float(fire[attack].mean()) if attack.any() else np.nan,
                    'capture_fpr':float(fire[benign].mean()) if benign.any() else np.nan,
                    'false_positive_rows':int((fire&benign).sum()),'threshold':threshold,
                    'calibration_captures':';'.join(cals),'calibration_details':json.dumps(details),
                    'train_test_duplicate_vectors_removed':removed,'training_captures':len(train_names),
                    'families_absent_from_source_training':';'.join(sorted(set(cfg.values())-{'Benign'}-set(family_classes)))})
                for family in sorted(set(cfg.values())-{'Benign'}):
                    mask=y==family
                    j=classes.index(family) if family in classes else None
                    pr=float(average_precision_score(mask.astype(int),pp[:,j])) if j is not None and mask.any() and benign.any() else np.nan
                    recall=float(((out[mask]==family)&fire[mask]).mean()) if mask.any() else np.nan
                    fpr=float(((out[benign]==family)&fire[benign]).mean()) if benign.any() else np.nan
                    famrows.append({'seed':seed,'train_dataset':source_dataset,'test_dataset':target_dataset,
                        'heldout_capture':name,'family':family,'support':int(mask.sum()),
                        'recall_correct_family_at_threshold':recall,'false_positive_rate_attributed_to_family':fpr,
                        'pr_auc_ovr':pr,'family_absent_from_training':family not in classes})
            calibrows.append({'seed':seed,'train_dataset':source_dataset,'test_dataset':target_dataset,
                'calibration_captures':';'.join(cals),'training_captures':';'.join(train_names),
                'training_classes':';'.join(classes),'threshold':threshold,'calibration_details':json.dumps(details),
                'train_test_duplicate_vectors_removed':removed})
            print(f'Completed {source_dataset} -> {target_dataset}, seed {seed}',flush=True)
    cap=pd.DataFrame(caprows); fam=pd.DataFrame(famrows)
    cap.to_csv(OUT/'cross_dataset_family_per_capture.csv',index=False)
    fam.to_csv(OUT/'cross_dataset_family_metrics.csv',index=False)
    pd.DataFrame(calibrows).to_csv(OUT/'cross_dataset_calibration_and_coverage.csv',index=False)
    summary=cap.groupby(['train_dataset','test_dataset','seed']).agg(mean_attack_recall=('attack_recall','mean'),
        mean_capture_fpr=('capture_fpr','mean'),worst_capture_fpr=('capture_fpr','max'),
        false_positive_rows=('false_positive_rows','sum'),benign_rows=('benign_rows','sum')).reset_index()
    summary['pooled_fpr']=summary.false_positive_rows/summary.benign_rows.replace(0,np.nan)
    summary.to_csv(OUT/'cross_dataset_family_seed_summary.csv',index=False)
    fsum=fam[fam.support>0].groupby(['train_dataset','test_dataset','family']).agg(
        recall_mean=('recall_correct_family_at_threshold','mean'),recall_sd=('recall_correct_family_at_threshold','std'),
        mean_family_fpr=('false_positive_rate_attributed_to_family','mean'),worst_family_fpr=('false_positive_rate_attributed_to_family','max'),
        mean_pr_auc=('pr_auc_ovr','mean'),test_captures=('heldout_capture','nunique'),
        absent_train_folds=('family_absent_from_training','sum')).reset_index()
    fsum.to_csv(OUT/'cross_dataset_family_rollup.csv',index=False)
    print(summary.to_string(index=False)); print(fsum.to_string(index=False))

if __name__=='__main__': main()
