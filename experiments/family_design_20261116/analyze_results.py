"""Create reliability labels and human-readable step report from saved evaluations."""
from __future__ import annotations
import json
from pathlib import Path
import numpy as np
import pandas as pd

ROOT=Path(__file__).resolve().parents[2]
OUT=Path(__file__).resolve().parent
BASE=ROOT/'experiments/failing_types_20261113'

def label_status(mean_recall,share_over70,worst_fpr,n_captures):
    if n_captures<2: return 'untestable'
    if share_over70>0.5 and worst_fpr<=0.02: return 'reliable'
    return 'partial' if mean_recall>=0.20 else 'experimental'

def main():
    baseline=pd.read_csv(BASE/'per_type_all_seeds.csv')
    baseline=baseline[(baseline.variant=='multiclass_77')&(baseline.model=='xgboost')]
    bmetrics=pd.read_csv(BASE/'capture_metrics_all_seeds.csv')
    bmetrics=bmetrics[(bmetrics.variant=='multiclass_77')&(bmetrics.model=='xgboost')]
    bmetrics['false_positive_rows']=(bmetrics.pooled_fpr*bmetrics.benign_rows).fillna(0).round().astype(int)
    worst=float(bmetrics.worst_capture_fpr.max())
    rows=[]
    for typ,g in baseline.groupby('attack_type'):
        cap=g.groupby('heldout_capture').detected_recall.mean()
        mean=float(cap.mean()); share=float((cap>.70).mean()); n=int(cap.size)
        rows.append({'item_type':'attack_type','label':typ,'captures':n,'capture_ids':';'.join(cap.index.astype(str)),
            'mean_recall_capture_weighted':mean,'capture_recall_sd':float(cap.std(ddof=1)) if n>1 else np.nan,
            'captures_over_70pct_recall':int((cap>.70).sum()),'share_captures_over_70pct':share,
            'model_worst_capture_fpr':worst,'reliability':'low-confidence' if n==2 else 'standard',
            'status':label_status(mean,share,worst,n),'evidence':'five-seed 12-type baseline; recall averaged across seeds within capture'})
    type_df=pd.DataFrame(rows)
    fam=pd.read_csv(OUT/'family_per_class_3seeds.csv')
    fam=fam[(fam.variant=='primary_5')&(fam.support>0)]
    fm=pd.read_csv(OUT/'family_capture_metrics_3seeds.csv'); fm=fm[fm.variant=='primary_5']
    fam_worst=float(fm.capture_fpr.max())
    frows=[]
    for family,g in fam.groupby('family'):
        cap=g.groupby('heldout_capture').recall_correct_family_at_threshold.mean()
        mean=float(cap.mean()); share=float((cap>.70).mean()); n=int(cap.size)
        pr=float(g.groupby('heldout_capture').pr_auc_ovr.mean().mean())
        frows.append({'item_type':'family','label':family,'captures':n,'capture_ids':';'.join(cap.index.astype(str)),
            'mean_recall_capture_weighted':mean,'capture_recall_sd':float(cap.std(ddof=1)) if n>1 else np.nan,
            'captures_over_70pct_recall':int((cap>.70).sum()),'share_captures_over_70pct':share,
            'model_worst_capture_fpr':fam_worst,'mean_ovr_pr_auc':pr,
            'reliability':'low-confidence' if n==2 else 'standard',
            'status':label_status(mean,share,fam_worst,n),'evidence':'three-seed five-family model; recall averaged across seeds within positive capture'})
    fam_df=pd.DataFrame(frows)
    combined=pd.concat([type_df,fam_df],ignore_index=True,sort=False)
    combined.to_csv(OUT/'reliability_labels.csv',index=False)
    # Seed means and paired 12-type baseline in same capture-fold units.
    rawfam=pd.read_csv(OUT/'family_capture_metrics_3seeds.csv')
    rawfam['false_positive_rows']=(rawfam.capture_fpr*rawfam.benign_rows).fillna(0).round().astype(int)
    fs=rawfam.groupby(['variant','seed']).agg(mean_attack_recall=('attack_recall','mean'),
        mean_capture_pr_auc=('attack_pr_auc','mean'),mean_capture_fpr=('capture_fpr','mean'),
        worst_capture_fpr=('capture_fpr','max'),mean_correct_family_recall=('end_to_end_correct_family_recall','mean'),
        false_positive_rows=('false_positive_rows','sum'),benign_rows=('benign_rows','sum')).reset_index()
    fs['pooled_fpr']=fs.false_positive_rows/fs.benign_rows.replace(0,np.nan)
    fs.to_csv(OUT/'family_seed_summary_3seeds.csv',index=False)
    famsum=fs.groupby('variant').agg(seeds=('seed','nunique'),
        attack_recall_mean=('mean_attack_recall','mean'),attack_recall_sd_across_seeds=('mean_attack_recall','std'),
        mean_capture_pr_auc=('mean_capture_pr_auc','mean'),mean_capture_pr_auc_sd=('mean_capture_pr_auc','std'),
        mean_capture_fpr=('mean_capture_fpr','mean'),mean_capture_fpr_sd=('mean_capture_fpr','std'),
        pooled_fpr=('pooled_fpr','mean'),worst_capture_fpr=('worst_capture_fpr','max'),
        mean_correct_family_recall=('mean_correct_family_recall','mean')).reset_index()
    famsum.to_csv(OUT/'family_summary_3seeds.csv',index=False)
    bs=bmetrics[bmetrics.seed.isin([42,43,44])].groupby('seed').agg(
        mean_attack_recall=('attack_recall_at_1pct_cal_fpr','mean'),mean_capture_fpr=('pooled_fpr','mean'),
        worst_capture_fpr=('worst_capture_fpr','max'),mean_capture_pr_auc=('pr_auc_attack','mean'),
        false_positive_rows=('false_positive_rows','sum'),benign_rows=('benign_rows','sum')).reset_index()
    bs['pooled_fpr']=bs.false_positive_rows/bs.benign_rows.replace(0,np.nan)
    bs['variant']='separate_12_type'
    bs.to_csv(OUT/'12type_seed_summary.csv',index=False)
    # Existing baseline five-seed results remain source for type reliability labels.
    combined_json={'reliability_rule':{
        'reliable':'recall >70% on more than half of positive held-out captures AND model worst-capture FPR <=2%',
        'partial':'not reliable, but capture-weighted mean recall >=20%',
        'experimental':'not reliable and capture-weighted mean recall <20%',
        'low_confidence':'exactly two positive capture files; appended independently of status',
        'untestable':'fewer than two positive captures'},
        'type_model_worst_capture_fpr':worst,'family_model_worst_capture_fpr':fam_worst,
        'type_results_seed_count':int(baseline.seed.nunique()),'family_results_seed_count':int(fam.seed.nunique()),
        'exploratory':True,'type_rows':type_df.to_dict(orient='records'),'family_rows':fam_df.to_dict(orient='records')}
    (OUT/'reliability_labels.json').write_text(json.dumps(combined_json,indent=2,allow_nan=True),encoding='utf-8')
    # Reusable result snippets for final documentation.
    fseed=fam.groupby(['family','seed']).agg(seed_recall=('recall_correct_family_at_threshold','mean'),
        seed_pr_auc=('pr_auc_ovr','mean')).reset_index()
    fcap=fam.groupby('family').heldout_capture.nunique().rename('positive_captures')
    fam_capture=fseed.groupby('family').agg(recall_mean_across_seed_means=('seed_recall','mean'),
        recall_sd_across_seed_means=('seed_recall','std'),mean_ovr_pr_auc=('seed_pr_auc','mean'),
        pr_auc_sd_across_seed_means=('seed_pr_auc','std'),seeds=('seed_recall','count')).join(fcap).reset_index()
    fam_capture.to_csv(OUT/'family_performance_rollup.csv',index=False)
    # Human-readable report.
    boot=pd.read_csv(OUT/'family_vs_12type_bootstrap.csv')
    s=famsum
    lines=['# Family-level IDS redesign: initial results','',
      '## Step 1 — family definitions','',
      '`families.json` records the requested five-family taxonomy, an exploratory three-family coarsening, and the separate 12-type taxonomy. The primary map is: DoS/DDoS (five DoS and DDoS types), Brute_force (FTP/SSH/Web brute force), Web_attack (SQL injection/XSS), Botnet, and Infiltration. The coarse “Other attack” group pools unlike behaviors and is only a label-granularity sensitivity check.','',
      '## Step 2 — capture-held-out comparison','',
      'The primary model used XGBoost with the existing 77 features, cap of 1,000 rows per raw label, 18 capture-held-out folds, and seeds 42–44. For every fold, one or two designated benign captures were kept out of training; per-capture 99th-percentile thresholds were combined conservatively using the maximum. Exact train/test feature-vector duplicates were removed. These reduced-sample results are exploratory.','',
      '| Variant | Mean attack recall ± SD across 3 seed means | Mean capture PR-AUC ± SD | Mean capture FPR | Pooled FPR | Worst-capture FPR |','|---|---:|---:|---:|---:|---:|']
    # Put separate 12-type baseline first, then coarse and primary.
    # Baseline by seed summary for comparable three seeds.
    br=bs.agg({'mean_attack_recall':['mean','std'],'mean_capture_pr_auc':['mean','std'],'mean_capture_fpr':['mean','std'],'worst_capture_fpr':['max']})
    bp=float(bs.pooled_fpr.mean())
    lines.append(f"| separate_12_type | {br.loc['mean','mean_attack_recall']:.1%} ± {br.loc['std','mean_attack_recall']:.1%} | {br.loc['mean','mean_capture_pr_auc']:.3f} ± {br.loc['std','mean_capture_pr_auc']:.3f} | {br.loc['mean','mean_capture_fpr']:.2%} ± {br.loc['std','mean_capture_fpr']:.2%} | {bp:.2%} | {br.loc['max','worst_capture_fpr']:.2%} |")
    for _,r in s.iterrows():
        lines.append(f"| {r.variant} | {r.attack_recall_mean:.1%} ± {r.attack_recall_sd_across_seeds:.1%} | {r.mean_capture_pr_auc:.3f} ± {r.mean_capture_pr_auc_sd:.3f} | {r.mean_capture_fpr:.2%} ± {r.mean_capture_fpr_sd:.2%} | {r.pooled_fpr:.2%} | {r.worst_capture_fpr:.2%} |")
    lines.extend(['','Per-family recall and one-vs-rest PR-AUC are in `family_performance_rollup.csv`; full seed/capture details are in `family_capture_metrics_3seeds.csv`, `family_per_class_3seeds.csv`, and `family_confusion_3seeds.csv`.','',
      '### Paired capture bootstrap against the 12-type model','',
      '| Family taxonomy | Mean recall difference | 95% capture-bootstrap interval | Interpretation |','|---|---:|---:|---|'])
    for _,r in boot.iterrows():
        lines.append(f"| {r.variant} | {r.mean_recall_difference:+.1%} | [{r.bootstrap_95ci_low:+.1%}, {r.bootstrap_95ci_high:+.1%}] | {'gain supported' if r.gain_established else 'interval includes zero; no established gain'} |")
    lines.extend(['','The requested five-family model’s estimated gain over the 12-type baseline is not statistically established: its paired capture-bootstrap interval includes zero. Per the stop rule, the 20/30/40-feature search and the new two-level subtype architecture are skipped. The existing 12-type model remains available as the separate-class baseline.','',
      '## Step 4 — reliability labels','',
      'Rule: “reliable” requires recall above 70% on more than half of positive held-out captures and the model’s worst-capture FPR at or below 2%. “Partial” means that rule is not met but capture-weighted mean recall is at least 20%; otherwise “experimental.” Exactly two positive captures is marked low-confidence regardless of status. The 12-type entries use five-seed baseline data; family entries use the new three-seed model.','',
      '| Kind | Label | Captures | Mean recall | Captures >70% | Worst FPR | Confidence | Status |','|---|---|---:|---:|---:|---:|---|---|'])
    for _,r in combined.iterrows():
        lines.append(f"| {r.item_type} | {r.label} | {int(r.captures)} | {r.mean_recall_capture_weighted:.1%} | {int(r.captures_over_70pct_recall)}/{int(r.captures)} | {r.model_worst_capture_fpr:.2%} | {r.reliability} | {r.status} |")
    lines.extend(['','## Skipped and pending tasks','',
      '- **Task 3, stable 20/30/40-feature selection:** skipped by the no-established-family-gain stop rule. No held-out data was used to select features.','- **Task 5, two-level detector/family/subtype output:** skipped by the same stop rule.','- **Task 6, conservative threshold:** completed at 1.0% and 0.5% calibration targets using the same three seeds and LOCO folds. See `family_threshold_comparison.csv` and `family_threshold_0_5_per_family.csv`.','- **Task 7, cross-dataset transfer:** completed in both directions using source-only calibration; see the `cross_dataset_family_*.csv` outputs.','- **Task 8, optional datasets:** LycoS-IDS2017, LycoS-Unicas-IDS2018, CIC-DDoS2019, and CTU-13 were not found locally. UNSW-NB15 and CIC-IDS Collection are present but do not support this direct 77-feature capture-held-out comparison.','',
      '## Provisional verdict','',
      'No variant is ready for a production trial. The five-family model has roughly 23% mean attack recall and 2.0% worst-capture FPR over these three reduced-sample seeds; it does not establish a gain over the 12-type baseline. The 12-type model also misses most attacks and its recorded five-seed worst-capture FPR exceeds the requested 2% reliability bound. These are exploratory estimates from only 18 capture files, and most attack families have two or three positive captures.'])
    # Add concise per-family, threshold, transfer, and data-gap tables before the verdict.
    marker=lines.index('## Provisional verdict')
    extra=['### Five-family detection results','',
      '| Family | Positive captures | Recall mean ± seed SD | Mean one-vs-rest PR-AUC |','|---|---:|---:|---:|']
    for _,r in fam_capture.iterrows():
        extra.append(f"| {r.family} | {int(r.positive_captures)} | {r.recall_mean_across_seed_means:.1%} ± {r.recall_sd_across_seed_means:.1%} | {r.mean_ovr_pr_auc:.3f} |")
    extra.extend(['','The five-family taxonomy modestly raises estimated attack recall by 0.6 percentage points, but its 95% paired capture-bootstrap interval is −5.0 to +7.0 points. That interval includes no change, so the apparent gain may be sampling noise.'])
    tcomp=pd.read_csv(OUT/'family_threshold_comparison.csv')
    cross=pd.read_csv(OUT/'cross_dataset_family_seed_summary.csv')
    cross_roll=pd.read_csv(OUT/'cross_dataset_family_rollup.csv')
    optional={'LycoS-IDS2017':False,'LycoS-Unicas-IDS2018':False,'CIC-DDoS2019':False,'CTU-13':False,
              'UNSW-NB15':True,'CIC-IDS Collection':True}
    (OUT/'optional_dataset_presence.json').write_text(json.dumps(optional,indent=2),encoding='utf-8')
    missing=[
      {'family':'Botnet','remaining_need':'More independent Botnet scenarios and benign captures; CTU-13 could help only after schema harmonization and capture-level labeling.'},
      {'family':'Brute_force','remaining_need':'Independent FTP, SSH, and Web-BruteForce sessions; specifically add SSH captures and separate the three brute-force modalities.'},
      {'family':'DoS_DDoS','remaining_need':'More held-out DDoS and each named DoS subtype across varied days; CIC-DDoS2019 can add DDoS, but not the CIC DoS subtypes without compatible labels/features.'},
      {'family':'Infiltration','remaining_need':'Multiple independent Infiltration scenarios plus varied benign network captures; current recall is near zero.'},
      {'family':'Web_attack','remaining_need':'More independent SQL-Injection and Web-XSS captures; present SQL support is especially small.'},
    ]
    pd.DataFrame(missing).to_csv(OUT/'remaining_data_by_family.csv',index=False)
    extra.extend(['','## Step 6 — threshold sensitivity','',
      '| Calibration target | Attack recall mean ± seed SD | Mean capture FPR | Pooled FPR | Worst-capture FPR |','|---|---:|---:|---:|---:|'])
    for _,r in tcomp.iterrows():
        extra.append(f"| {r.target} | {r.attack_recall_mean:.1%} ± {r.attack_recall_sd:.1%} | {r.mean_capture_fpr:.2%} | {r.pooled_fpr:.2%} | {r.worst_capture_fpr:.2%} |")
    t1=tcomp[tcomp.target.eq('1.0%')].iloc[0]; t05=tcomp[tcomp.target.eq('0.5%')].iloc[0]
    extra.extend(['',f"The 0.5% target costs {t1.attack_recall_mean-t05.attack_recall_mean:.1%} recall compared with 1%, while worst-capture FPR falls from {t1.worst_capture_fpr:.2%} to {t05.worst_capture_fpr:.2%}. Even this conservative setting leaves attack recall low and worst-capture FPR above 1%.",'',
      '## Step 7 — cross-dataset family transfer','',
      '| Train → test | Attack recall mean ± seed SD | Mean capture FPR | Worst capture FPR |','|---|---:|---:|---:|'])
    for (tr,te),g in cross.groupby(['train_dataset','test_dataset']):
        extra.append(f"| {tr} → {te} | {g.mean_attack_recall.mean():.1%} ± {g.mean_attack_recall.std():.1%} | {g.mean_capture_fpr.mean():.2%} | {g.worst_capture_fpr.max():.2%} |")
    extra.extend(['','Per-family recalls and family-attributed benign FPRs for both directions are in `cross_dataset_family_rollup.csv`. Results are strongly directional and neither direction meets the “near 1% on every capture” goal.','',
      '| Transfer direction | Family | Recall | Mean family-attributed FPR | Worst family-attributed FPR |','|---|---|---:|---:|---:|'])
    for _,r in cross_roll.iterrows():
        extra.append(f"| {r.train_dataset} → {r.test_dataset} | {r.family} | {r.recall_mean:.1%} | {r.mean_family_fpr:.2%} | {r.worst_family_fpr:.2%} |")
    extra.extend(['','## Step 8 — optional local datasets','',
      'No LycoS-IDS2017, LycoS-Unicas-IDS2018, CIC-DDoS2019, or CTU-13 files were found. UNSW-NB15 and CIC-IDS Collection are present, but have incompatible or incomplete schema/provenance for this direct 77-feature capture-held-out comparison.','',
      '## Remaining data by family','',
      '| Family | What is still needed |','|---|---|'])
    for r in missing: extra.append(f"| {r['family']} | {r['remaining_need']} |")
    lines[marker:marker]=extra
    (OUT/'RESULTS.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    print('Wrote reliability and report outputs.')

if __name__=='__main__': main()
