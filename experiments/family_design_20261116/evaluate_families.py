"""Three-seed capture-held-out family evaluation using the existing prepared samples."""
from __future__ import annotations
import json, math
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

ROOT=Path(__file__).resolve().parents[2]
OUT=Path(__file__).resolve().parent
BASE=ROOT/'experiments/failing_types_20261113'
import sys
sys.path.insert(0,str(ROOT))
SEEDS=(42,43,44)
CAL_TOKENS=('Benign-Monday','Portscan-Friday')
from pipeline.data_pipeline import FEATURES
from evaluation import ten_type_candidate as project

def read_seed(seed):
    frames={}
    base=BASE/f'seed_{seed}/merged/sampled_1000/combined_captures'
    for path in sorted(base.glob('*/*.parquet')):
        f=pd.read_parquet(path)
        dataset=str(f.source_dataset.iloc[0]); cap=str(f.capture.iloc[0]); name=f'{dataset}__{cap}'
        f=f.rename(columns={'raw_label':'__raw_label','capture':'__capture','source_dataset':'__dataset','label':'__type'})
        f['__type']=f['__raw_label'].map(project.canonical_type)
        f=f[f['__type'].isin(['Benign',*project.ATTACK_TYPES])].drop_duplicates(subset=FEATURES+['__type']).reset_index(drop=True)
        f['__capture']=name
        frames[name]=f
    if len(frames)!=18: raise RuntimeError(f'seed {seed}: expected 18 captures, got {len(frames)}')
    return frames

def choose_calibration(frames,heldout):
    selected=[]
    for name in frames:
        if any(t in name for t in CAL_TOKENS) and name!=heldout:
            if int(frames[name]['__type'].eq('Benign').sum())>=100:
                selected.append(name)
                if len(selected)==2: break
    if not selected: raise RuntimeError(f'No separate benign calibration capture for {heldout}')
    return selected

def remove_test_duplicates(train,test,target_col):
    # Dataset is small (capped rows); hashing matches the reused baseline rule.
    th=set(pd.util.hash_pandas_object(test[FEATURES],index=False).tolist())
    h=pd.util.hash_pandas_object(train[FEATURES],index=False)
    keep=~h.isin(th)
    return train.loc[keep].reset_index(drop=True),int((~keep).sum())

def fit_predict(train,cal,test,seed,target_fpr=.01):
    enc=LabelEncoder().fit(train['__target'])
    model=XGBClassifier(objective='multi:softprob',num_class=len(enc.classes_),eval_metric='mlogloss',
        n_estimators=80,max_depth=6,learning_rate=.08,subsample=.85,colsample_bytree=.85,
        tree_method='hist',random_state=seed,n_jobs=1)
    model.fit(train[FEATURES],enc.transform(train['__target']))
    pcal=model.predict_proba(cal[FEATURES]); ptest=model.predict_proba(test[FEATURES])
    classes=list(enc.classes_); attack_idx=[i for i,c in enumerate(classes) if c!='Benign']
    cal_attack=pcal[:,attack_idx].max(axis=1)
    thresholds=[]; detail={}
    for cap in cal['__capture'].unique():
        vals=cal_attack[cal['__capture'].eq(cap).to_numpy()]
        q=float(np.quantile(vals,1-target_fpr,method='higher')); t=float(np.nextafter(q,math.inf))
        thresholds.append(t); detail[cap]={'benign_rows':len(vals),'threshold':t,'observed_fpr':float(np.mean(vals>=t))}
    threshold=max(thresholds)
    score=ptest[:,attack_idx].max(axis=1); pred_family=np.asarray(classes,dtype=object)[ptest.argmax(axis=1)]
    return score,pred_family,ptest,classes,threshold,detail

def run_variant(mapping_name,mapping,seeds=SEEDS):
    metrics=[]; family_rows=[]; confusions=[]; thresholds=[]
    for seed in seeds:
        print(f'Loading seed {seed}, taxonomy {mapping_name}',flush=True)
        frames=read_seed(seed)
        for f in frames.values():
            f['__target']=f['__type'].map(mapping)
        names=list(frames)
        for heldout in names:
            print(f'  seed {seed} {mapping_name}: fitting fold {heldout}',flush=True)
            cals=choose_calibration(frames,heldout)
            train_names=[n for n in names if n not in {heldout,*cals}]
            train=pd.concat([frames[n] for n in train_names],ignore_index=True)
            cal=pd.concat([frames[n].loc[frames[n]['__type'].eq('Benign')] for n in cals],ignore_index=True)
            test=frames[heldout]
            train,removed=remove_test_duplicates(train,test,'__target')
            score,pred,p,classes,threshold,cal_detail=fit_predict(train,cal,test,seed,.01)
            y=test['__target'].to_numpy(); is_attack=y!='Benign'; detected=score>=threshold
            fpr=float(detected[~is_attack].mean()) if (~is_attack).any() else np.nan
            recall=float(detected[is_attack].mean()) if is_attack.any() else np.nan
            pr=float(average_precision_score(is_attack.astype(int),score)) if is_attack.any() and (~is_attack).any() else np.nan
            fams=[c for c in classes if c!='Benign']
            row={'seed':seed,'variant':mapping_name,'heldout_capture':heldout,'test_rows':len(test),
                 'benign_rows':int((~is_attack).sum()),'attack_rows':int(is_attack.sum()),
                 'false_positive_rows':int((detected&~is_attack).sum()),
                 'threshold':threshold,'threshold_calibration':json.dumps(cal_detail),
                 'attack_recall':recall,'attack_pr_auc':pr,'capture_fpr':fpr,
                 'duplicate_train_vectors_removed':removed,'training_captures':len(train_names),
                 'end_to_end_correct_family_recall':float(((pred[is_attack]==y[is_attack])&detected[is_attack]).mean()) if is_attack.any() else np.nan,
                 'family_accuracy_given_detected':float((pred[is_attack&detected]==y[is_attack&detected]).mean()) if (is_attack&detected).any() else np.nan}
            metrics.append(row)
            thresholds.append({'seed':seed,'variant':mapping_name,'heldout_capture':heldout,'threshold':threshold,'calibration':json.dumps(cal_detail)})
            for fam in fams:
                mask=y==fam; benign=~is_attack
                idx=classes.index(fam)
                fam_pr=float(average_precision_score(mask.astype(int),p[:,idx])) if mask.any() and (~mask).any() else np.nan
                fam_recall=float(((pred[mask]==fam)&detected[mask]).mean()) if mask.any() else np.nan
                fam_support=int(mask.sum())
                family_rows.append({'seed':seed,'variant':mapping_name,'heldout_capture':heldout,'family':fam,
                    'support':fam_support,'recall_correct_family_at_threshold':fam_recall,'pr_auc_ovr':fam_pr,
                    'missed_or_wrong_family':int(mask.sum()-((pred[mask]==fam)&detected[mask]).sum())})
            out=np.where(detected,pred,'NOT_FLAGGED')
            mat=pd.crosstab(pd.Series(y,name='actual'),pd.Series(out,name='output'))
            for actual,vec in mat.iterrows():
                for outname,count in vec.items():
                    if count: confusions.append({'seed':seed,'variant':mapping_name,'heldout_capture':heldout,'actual':actual,'output':outname,'count':int(count)})
            print(f'  finished fold {heldout}',flush=True)
        print(f'Completed seed {seed}, taxonomy {mapping_name}',flush=True)
    return pd.DataFrame(metrics),pd.DataFrame(family_rows),pd.DataFrame(confusions),pd.DataFrame(thresholds)

def main():
    cfg=json.loads((OUT/'families.json').read_text(encoding='utf-8'))
    allm=[]; allf=[]; allc=[]; allt=[]
    for name,key in [('primary_5_family_mapping','primary_5'),('coarse_3_family_mapping','coarse_3')]:
        m,f,c,t=run_variant(key,cfg[name])
        allm.append(m); allf.append(f); allc.append(c); allt.append(t)
    metrics=pd.concat(allm,ignore_index=True); per=pd.concat(allf,ignore_index=True); conf=pd.concat(allc,ignore_index=True)
    metrics.to_csv(OUT/'family_capture_metrics_3seeds.csv',index=False)
    per.to_csv(OUT/'family_per_class_3seeds.csv',index=False)
    conf.to_csv(OUT/'family_confusion_3seeds.csv',index=False)
    pd.concat(allt,ignore_index=True).to_csv(OUT/'family_thresholds_3seeds.csv',index=False)
    baseline=pd.read_csv(BASE/'capture_metrics_all_seeds.csv')
    baseline=baseline[(baseline.seed.isin(SEEDS))&baseline.variant.eq('multiclass_77')&baseline.model.eq('xgboost')].copy()
    baseline=baseline[['seed','heldout_capture','attack_recall_at_1pct_cal_fpr','pooled_fpr']]
    baseline.to_csv(OUT/'baseline_12type_capture_metrics_3seeds.csv',index=False)
    paired=[]
    for variant in ['primary_5','coarse_3']:
        fam=metrics[metrics.variant.eq(variant)].groupby(['seed','heldout_capture']).attack_recall.mean().rename('family')
        base=baseline.groupby(['seed','heldout_capture']).attack_recall_at_1pct_cal_fpr.mean().rename('types')
        z=pd.concat([fam,base],axis=1).dropna().reset_index()
        z['difference_family_minus_12type']=z.family-z.types
        # Average paired seed differences within capture before capture-cluster bootstrap.
        d=z.groupby('heldout_capture').difference_family_minus_12type.mean().to_numpy()
        rng=np.random.default_rng(20261116); b=rng.integers(0,len(d),(10000,len(d)))
        boots=d[b].mean(axis=1) if len(d) else np.array([])
        lo=float(np.quantile(boots,.025)) if len(boots) else np.nan; hi=float(np.quantile(boots,.975)) if len(boots) else np.nan
        paired.append({'variant':variant,'paired_captures':len(d),'mean_recall_difference':float(d.mean()) if len(d) else np.nan,
            'bootstrap_95ci_low':lo,'bootstrap_95ci_high':hi,
            'bootstrap_two_sided_sign_probability':float(2*min(np.mean(boots<=0),np.mean(boots>=0))) if len(boots) else np.nan,
            'gain_established':bool(lo>0),'interpretation':'Paired capture-cluster bootstrap, averaging three paired seeds per capture; exploratory reduced-sample estimate.'})
    boot=pd.DataFrame(paired); boot.to_csv(OUT/'family_vs_12type_bootstrap.csv',index=False)
    seed_summary=metrics.groupby(['variant','seed']).agg(
        mean_attack_recall=('attack_recall','mean'),mean_capture_pr_auc=('attack_pr_auc','mean'),
        mean_capture_fpr=('capture_fpr','mean'),worst_capture_fpr=('capture_fpr','max'),
        mean_correct_family_recall=('end_to_end_correct_family_recall','mean'),
        false_positive_rows=('false_positive_rows','sum'),benign_rows=('benign_rows','sum')).reset_index()
    seed_summary['pooled_fpr']=seed_summary.false_positive_rows/seed_summary.benign_rows.replace(0,np.nan)
    seed_summary.to_csv(OUT/'family_seed_summary_3seeds.csv',index=False)
    summary=seed_summary.groupby('variant').agg(seeds=('seed','nunique'),
        attack_recall_mean=('mean_attack_recall','mean'),attack_recall_sd_across_seeds=('mean_attack_recall','std'),
        mean_capture_pr_auc=('mean_capture_pr_auc','mean'),mean_capture_pr_auc_sd=('mean_capture_pr_auc','std'),
        mean_capture_fpr=('mean_capture_fpr','mean'),mean_capture_fpr_sd=('mean_capture_fpr','std'),
        pooled_fpr=('pooled_fpr','mean'),worst_capture_fpr=('worst_capture_fpr','max'),
        mean_correct_family_recall=('mean_correct_family_recall','mean')).reset_index()
    summary.to_csv(OUT/'family_summary_3seeds.csv',index=False)
    (OUT/'step2_status.json').write_text(json.dumps({'seed_count':3,'bootstrap':boot.to_dict(orient='records'),
        'family_gain_established':bool(boot.loc[boot.variant.eq('primary_5'),'gain_established'].iloc[0]),
        'stop_rule_tasks_3_and_5_beyond_baseline':'skip' if not bool(boot.loc[boot.variant.eq('primary_5'),'gain_established'].iloc[0]) else 'continue'},indent=2),encoding='utf-8')
    print(summary.to_string(index=False)); print('\nPaired family vs 12-type:'); print(boot.to_string(index=False))

if __name__=='__main__': main()
