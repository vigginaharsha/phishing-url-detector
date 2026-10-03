"""
Model Evaluation Module for Phishing Detection.

Computes comprehensive metrics (Accuracy, Precision, Recall, F1, Confusion Matrix, ROC-AUC)
and formats comparison summaries.
"""

from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, roc_auc_score
)


def evaluate_model(model, X_test, y_test, model_name: str = "Model") -> dict:
    """
    Evaluates a trained classifier on test data.
    
    Returns a dictionary of performance metrics.
    """
    y_pred = model.predict(X_test)
    
    # Probabilities for ROC-AUC if model supports predict_proba
    if hasattr(model, "predict_proba"):
        y_proba = model.predict_proba(X_test)[:, 1]
        auc_score = round(float(roc_auc_score(y_test, y_proba)), 4)
    else:
        auc_score = None

    acc = round(float(accuracy_score(y_test, y_pred)), 4)
    prec = round(float(precision_score(y_test, y_pred, zero_division=0)), 4)
    rec = round(float(recall_score(y_test, y_pred, zero_division=0)), 4)
    f1 = round(float(f1_score(y_test, y_pred, zero_division=0)), 4)
    cm = confusion_matrix(y_test, y_pred).tolist()  # [[TN, FP], [FN, TP]]

    metrics = {
        'model_name': model_name,
        'accuracy': acc,
        'precision': prec,
        'recall': rec,
        'f1_score': f1,
        'roc_auc': auc_score,
        'confusion_matrix': cm
    }
    
    return metrics


def print_evaluation_summary(metrics: dict):
    """
    Prints a formatted summary of model performance.
    """
    print(f"\n==========================================")
    print(f" Model Performance: {metrics['model_name']}")
    print(f"==========================================")
    print(f" Accuracy:  {metrics['accuracy'] * 100:.2f}%")
    print(f" Precision: {metrics['precision'] * 100:.2f}%")
    print(f" Recall:    {metrics['recall'] * 100:.2f}%")
    print(f" F1 Score:  {metrics['f1_score'] * 100:.2f}%")
    if metrics['roc_auc'] is not None:
        print(f" ROC-AUC:   {metrics['roc_auc']:.4f}")
    
    cm = metrics['confusion_matrix']
    print(f" Confusion Matrix:")
    print(f"   True Negatives (Safe correctly identified):   {cm[0][0]}")
    print(f"   False Positives (Safe misclassified as Phish): {cm[0][1]}")
    print(f"   False Negatives (Phish misclassified as Safe): {cm[1][0]}")
    print(f"   True Positives (Phish correctly identified):  {cm[1][1]}")
    print(f"==========================================\n")
