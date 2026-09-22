[INFO] Loaded 2,209,288 rows x 11 columns from 'data\processed\cleaned_network_data_rf.csv'.

=== Three-Way Split — Row Counts & Class Balance ===
Total rows: 2,209,288  |  Train: 1,546,501 (70.00%)  |  Val: 331,393 (15.00%)  |  Test: 331,394 (15.00%)
                train_count  train_pct  val_count  val_pct  test_count  test_pct
Attack Type                                                                     
Normal Traffic      1392049    90.0128     298297  90.0131      298297   90.0128
DDoS                  89605     5.7940      19201   5.7940       19201    5.7940
Port Scanning         63486     4.1051      13604   4.1051       13604    4.1051
Bots                   1361     0.0880        291   0.0878         292    0.0881

[INFO] Training RandomForestClassifier on 1,546,501 rows with params: {'n_estimators': 300, 'max_depth': 20, 'min_samples_leaf': 5, 'class_weight': 'balanced', 'n_jobs': -1, 'random_state': 42}
[INFO] Training completed in 187.8s.

=== Train vs. Validation — Overfitting Check ===
Metric                     Train    Validation       Gap
Accuracy                  0.9959        0.9956    0.0003
Macro F1-Score            0.8317        0.8258    0.0059
[INFO] Train/Validation macro-F1 gap (0.0059) is within the 0.05 threshold — no strong overfitting signal.
[INFO] Validation — Bots class: precision=0.1871, recall=0.9656, f1=0.3134, support=291

======================================================================
FINAL TEST SET EVALUATION (untouched — first and only use)
======================================================================

--- Classification Report ---
                precision    recall  f1-score   support

          Bots     0.1782    0.9452    0.2998       292
          DDoS     0.9980    0.9991    0.9985     19201
Normal Traffic     0.9999    0.9951    0.9975    298297
 Port Scanning     0.9881    0.9996    0.9938     13604

      accuracy                         0.9954    331394
     macro avg     0.7910    0.9847    0.8224    331394
  weighted avg     0.9986    0.9954    0.9968    331394

>>> Bots (0.088% of data) on Test — precision=0.1782, recall=0.9452, f1=0.2998, support=292 rows

--- Labeled Confusion Matrix (rows = actual, columns = predicted) ---
                       pred_Bots  pred_DDoS  pred_Normal Traffic  pred_Port Scanning
actual_Bots                  276          0                   16                   0
actual_DDoS                    0      19184                   17                   0
actual_Normal Traffic       1273         39               296821                 164
actual_Port Scanning           0          0                    6               13598

--- Ranked Feature Importance ---
                             importance  importance_pct
Destination Port                 0.2344           23.44
Fwd Packet Length Mean           0.2116           21.16
Total Length of Fwd Packets      0.1649           16.49
Total Fwd Packets                0.0782            7.82
Flow Duration                    0.0716            7.16
Flow Bytes/s                     0.0654            6.54
Fwd Packet Length Min            0.0507            5.07
Fwd Packets/s                    0.0473            4.73
Flow IAT Std                     0.0431            4.31
Flow IAT Mean                    0.0327            3.27

[INFO] Model saved to 'models\random_forest_model.joblib' (61.35 MB).
