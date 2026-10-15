import argparse
import hashlib
import os
import random
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd
import torch
import torch.nn as nn
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from torch.utils.data import DataLoader, Dataset


BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"
ART_DIR = BASE_DIR / "artifacts"
ART_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_CSV_PATH = DATA_DIR / "phishing_simple.csv"
DEFAULT_MODEL_OUT = ART_DIR / "model.pt"

DEVICE = "cuda" if torch.cuda.is_available() else "cpu"

SEED = 42
DEFAULT_MAX_LEN = 512
DEFAULT_EPOCHS = 10
DEFAULT_BATCH_SIZE = 128 if DEVICE == "cuda" else 512
DEFAULT_LR = 1e-3
DEFAULT_WEIGHT_DECAY = 1e-4
DEFAULT_PATIENCE = 3


def set_seed(seed: int = 42):
    random.seed(seed)
    torch.manual_seed(seed)

    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()

    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)

    return h.hexdigest()


def normalize_url_for_cnn(s: str) -> str:
    """
    CNN 입력 전처리.

    핵심:
    - 도메인만 자르지 않음
    - path/query 제거하지 않음
    - URL 전체 문자열 사용
    - 소문자 변환
    """
    v = str(s or "").strip()

    if not v:
        return ""

    v = v.replace("\r", "").replace("\n", "").replace("\t", "")
    v = v.lower()

    return v


def map_label(v) -> int | None:
    s = str(v).strip().lower()

    if s in {"1", "true", "bad", "phishing", "phish", "malicious", "mal"}:
        return 1

    if s in {"0", "false", "good", "benign", "safe", "legitimate", "normal"}:
        return 0

    return None


def get_root_domain(url: str) -> str:
    """
    도메인 그룹 확인용.
    현재 split은 stratify split을 사용하지만, 데이터 확인용으로 유지.
    """
    u = str(url or "").strip().lower()

    if not u:
        return ""

    if "://" not in u:
        u = "https://" + u

    host = (urlparse(u).hostname or "").lower().strip()

    if not host:
        return ""

    if host.startswith("www."):
        host = host[4:]

    parts = [p for p in host.split(".") if p]

    if len(parts) <= 2:
        return host

    common_2level_suffixes = {
        "co.kr", "or.kr", "go.kr", "ac.kr",
        "co.uk", "ac.uk", "gov.uk",
        "com.au", "net.au", "org.au",
    }

    last2 = ".".join(parts[-2:])
    last3 = ".".join(parts[-3:])

    if last2 in common_2level_suffixes and len(parts) >= 3:
        return last3

    return last2


def load_dataset(csv_path: Path) -> pd.DataFrame:
    if not csv_path.exists():
        raise FileNotFoundError(f"CSV not found: {csv_path}")

    df = pd.read_csv(csv_path)
    cols_lower = {c.lower(): c for c in df.columns}

    url_col = cols_lower.get("url")
    domain_col = cols_lower.get("domain")
    label_col = cols_lower.get("label")

    if label_col is None:
        raise ValueError(f"label column not found. columns={list(df.columns)}")

    src_col = url_col or domain_col

    if src_col is None:
        raise ValueError(f"url/domain column not found. columns={list(df.columns)}")

    df = df[[src_col, label_col]].copy()
    df.columns = ["text", "label_raw"]

    df["text"] = df["text"].astype(str).map(normalize_url_for_cnn)
    df["label"] = df["label_raw"].map(map_label)

    df = df[df["text"].str.len() > 0]
    df = df[df["label"].isin([0, 1])]
    df = df.drop_duplicates(subset=["text"]).reset_index(drop=True)

    if len(df) < 100:
        raise ValueError("Too few valid rows after cleaning.")

    df["group"] = df["text"].map(get_root_domain)
    df = df[df["group"].str.len() > 0].reset_index(drop=True)

    print("[CSV PATH]", csv_path)
    print("[ROWS]", len(df))
    print("[LABEL COUNTS]")
    print(df["label"].value_counts())
    print("[SAMPLE]")
    print(df.head())

    return df


def build_vocab(texts: list[str]) -> dict[str, int]:
    chars = sorted(set("".join(texts)))
    return {ch: i + 1 for i, ch in enumerate(chars)}


def encode_url(text: str, vocab: dict[str, int], max_len: int) -> list[int]:
    arr = [vocab.get(ch, 0) for ch in text[:max_len]]

    if len(arr) < max_len:
        arr += [0] * (max_len - len(arr))

    return arr


class URLDataset(Dataset):
    def __init__(self, texts, labels, vocab, max_len):
        self.texts = list(texts)
        self.labels = list(labels)
        self.vocab = vocab
        self.max_len = max_len

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        x = encode_url(self.texts[idx], self.vocab, self.max_len)
        y = float(self.labels[idx])

        return (
            torch.tensor(x, dtype=torch.long),
            torch.tensor(y, dtype=torch.float32),
        )


class CharCNN(nn.Module):
    def __init__(self, vocab_size: int, emb_dim: int = 32, channels: int = 64):
        super().__init__()

        self.emb = nn.Embedding(vocab_size + 1, emb_dim, padding_idx=0)

        self.convs = nn.ModuleList([
            nn.Conv1d(emb_dim, channels, kernel_size=k, padding=k // 2)
            for k in [3, 5, 7]
        ])

        self.relu = nn.ReLU()
        self.pool_max = nn.AdaptiveMaxPool1d(1)
        self.pool_avg = nn.AdaptiveAvgPool1d(1)
        self.dropout = nn.Dropout(0.35)
        self.fc = nn.Linear(channels * 6, 1)

    def forward(self, x):
        x = self.emb(x)
        x = x.transpose(1, 2)

        features = []

        for conv in self.convs:
            c = self.relu(conv(x))

            max_pool = self.pool_max(c).squeeze(-1)
            avg_pool = self.pool_avg(c).squeeze(-1)

            features.append(max_pool)
            features.append(avg_pool)

        h = torch.cat(features, dim=1)
        h = self.dropout(h)

        return self.fc(h).squeeze(1)


def split_dataset(df: pd.DataFrame, val_size: float = 0.2):
    """
    학습 데이터 80%, 검증 데이터 20% 분리.
    stratify를 사용해서 정상/피싱 비율을 유지한다.
    """
    train_df, val_df = train_test_split(
        df,
        test_size=val_size,
        random_state=SEED,
        stratify=df["label"],
    )

    train_df = train_df.reset_index(drop=True)
    val_df = val_df.reset_index(drop=True)

    print("[TRAIN ROWS]", len(train_df))
    print("[VAL ROWS]", len(val_df))
    print("[TRAIN LABEL COUNTS]")
    print(train_df["label"].value_counts())
    print("[VAL LABEL COUNTS]")
    print(val_df["label"].value_counts())

    return train_df, val_df


def evaluate(model, loader, loss_fn):
    model.eval()

    losses = []
    all_probs = []
    all_labels = []

    with torch.no_grad():
        for x, y in loader:
            x = x.to(DEVICE)
            y = y.to(DEVICE)

            logits = model(x)
            loss = loss_fn(logits, y)

            probs = torch.sigmoid(logits)

            losses.append(float(loss.item()))
            all_probs.extend(probs.detach().cpu().numpy().tolist())
            all_labels.extend(y.detach().cpu().numpy().tolist())

    pred_labels = [1 if p >= 0.5 else 0 for p in all_probs]

    acc = accuracy_score(all_labels, pred_labels)
    precision = precision_score(all_labels, pred_labels, zero_division=0)
    recall = recall_score(all_labels, pred_labels, zero_division=0)
    f1 = f1_score(all_labels, pred_labels, zero_division=0)

    try:
        auc = roc_auc_score(all_labels, all_probs)
    except Exception:
        auc = 0.0

    cm = confusion_matrix(all_labels, pred_labels).tolist()

    return {
        "loss": sum(losses) / max(len(losses), 1),
        "accuracy": acc,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "auc": auc,
        "confusion_matrix": cm,
    }


def print_ppt_metrics_table(metrics: dict, save_path: Path | None = None):
    """
    PPT 캡처용 가로표 출력.
    학습 종료 후 터미널에 보기 좋은 표로 출력하고 txt 파일로도 저장한다.
    """
    cm = metrics.get("confusion_matrix", [[0, 0], [0, 0]])

    try:
        tn, fp = cm[0]
        fn, tp = cm[1]
    except Exception:
        tn = fp = fn = tp = 0

    accuracy = float(metrics.get("accuracy", 0.0))
    precision = float(metrics.get("precision", 0.0))
    recall = float(metrics.get("recall", 0.0))
    f1 = float(metrics.get("f1", 0.0))
    auc = float(metrics.get("auc", 0.0))

    lines = []

    lines.append("CNN 모델 검증 성능")
    lines.append("학습 데이터 80% / 검증 데이터 20%")
    lines.append("")
    lines.append("+------------+-----------+-----------+--------+----------+")
    lines.append("| Accuracy   | Precision | Recall    | F1     | AUC      |")
    lines.append("+------------+-----------+-----------+--------+----------+")
    lines.append(
        f"| {accuracy:>10.4f} | {precision:>9.4f} | {recall:>9.4f} | {f1:>6.4f} | {auc:>8.4f} |"
    )
    lines.append("+------------+-----------+-----------+--------+----------+")
    lines.append("")
    lines.append("Confusion Matrix")
    lines.append("+-------------+-------------+-------------+-------------+")
    lines.append("| TN       | FP       | FN       | TP       |")
    lines.append("+-------------+-------------+-------------+-------------+")
    lines.append(f"| {tn:>11} | {fp:>11} | {fn:>11} | {tp:>11} |")
    lines.append("+-------------+-------------+-------------+-------------+")

    text = "\n".join(lines)

    print("\n" + text + "\n")

    if save_path is not None:
        save_path.parent.mkdir(parents=True, exist_ok=True)
        save_path.write_text(text, encoding="utf-8")
        print(f"[PPT REPORT SAVED] {save_path}")


def train_model(
    *,
    csv_path: Path,
    model_out: Path,
    max_len: int,
    epochs: int,
    batch_size: int,
    lr: float,
    weight_decay: float,
    patience: int,
):
    set_seed(SEED)

    df = load_dataset(csv_path)
    train_df, val_df = split_dataset(df, val_size=0.2)

    vocab = build_vocab(train_df["text"].tolist())

    train_ds = URLDataset(
        train_df["text"].tolist(),
        train_df["label"].tolist(),
        vocab,
        max_len,
    )

    val_ds = URLDataset(
        val_df["text"].tolist(),
        val_df["label"].tolist(),
        vocab,
        max_len,
    )

    train_loader = DataLoader(
        train_ds,
        batch_size=batch_size,
        shuffle=True,
        num_workers=0,
    )

    val_loader = DataLoader(
        val_ds,
        batch_size=batch_size,
        shuffle=False,
        num_workers=0,
    )

    model = CharCNN(
        vocab_size=len(vocab),
        emb_dim=32,
        channels=64,
    ).to(DEVICE)

    labels = train_df["label"].tolist()
    pos_count = sum(1 for x in labels if x == 1)
    neg_count = sum(1 for x in labels if x == 0)

    if pos_count > 0:
        pos_weight_value = neg_count / max(pos_count, 1)
    else:
        pos_weight_value = 1.0

    pos_weight = torch.tensor([pos_weight_value], dtype=torch.float32, device=DEVICE)

    loss_fn = nn.BCEWithLogitsLoss(pos_weight=pos_weight)

    optimizer = torch.optim.AdamW(
        model.parameters(),
        lr=lr,
        weight_decay=weight_decay,
    )

    best_auc = -1.0
    best_state = None
    bad_epochs = 0

    print("[DEVICE]", DEVICE)
    print("[VOCAB SIZE]", len(vocab))
    print("[MAX_LEN]", max_len)
    print("[BATCH_SIZE]", batch_size)
    print("[POS_WEIGHT]", float(pos_weight_value))

    for epoch in range(1, epochs + 1):
        model.train()

        train_losses = []

        for x, y in train_loader:
            x = x.to(DEVICE)
            y = y.to(DEVICE)

            optimizer.zero_grad()

            logits = model(x)
            loss = loss_fn(logits, y)

            loss.backward()
            optimizer.step()

            train_losses.append(float(loss.item()))

        val_metrics = evaluate(model, val_loader, loss_fn)

        train_loss = sum(train_losses) / max(len(train_losses), 1)

        print(
            f"[EPOCH {epoch}] "
            f"train_loss={train_loss:.6f} "
            f"val_loss={val_metrics['loss']:.6f} "
            f"acc={val_metrics['accuracy']:.4f} "
            f"precision={val_metrics['precision']:.4f} "
            f"recall={val_metrics['recall']:.4f} "
            f"f1={val_metrics['f1']:.4f} "
            f"auc={val_metrics['auc']:.4f}"
        )

        if val_metrics["auc"] > best_auc:
            best_auc = val_metrics["auc"]
            best_state = {
                k: v.detach().cpu().clone()
                for k, v in model.state_dict().items()
            }
            bad_epochs = 0
        else:
            bad_epochs += 1

        if bad_epochs >= patience:
            print("[EARLY STOP]")
            break

    if best_state is None:
        raise RuntimeError("training failed: best_state is None")

    model.load_state_dict(best_state)

    final_metrics = evaluate(model, val_loader, loss_fn)

    print_ppt_metrics_table(
        final_metrics,
        save_path=ART_DIR / "cnn_metrics_report.txt",
    )

    model_out.parent.mkdir(parents=True, exist_ok=True)

    bundle = {
        "state_dict": model.state_dict(),
        "vocab": vocab,
        "max_len": max_len,
        "emb_dim": 32,
        "channels": 64,
        "version": "ml_fullurl_dl_v1",
        "model_type": "charcnn",
        "input_mode": "raw_full_url",
        "best_auc": best_auc,
        "metrics": final_metrics,
        "csv_path": str(csv_path),
        "csv_sha256": sha256_file(csv_path),
    }

    torch.save(bundle, model_out)

    print("\n[SAVED MODEL]", model_out)
    print("[BEST AUC]", best_auc)

    return final_metrics


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--csv",
        type=str,
        default=str(DEFAULT_CSV_PATH),
        help="학습 CSV 경로. 기본값: data/phishing_simple.csv",
    )

    parser.add_argument(
        "--out",
        type=str,
        default=str(DEFAULT_MODEL_OUT),
        help="저장할 모델 경로. 기본값: artifacts/model.pt",
    )

    parser.add_argument(
        "--max-len",
        type=int,
        default=int(os.getenv("MAX_LEN", DEFAULT_MAX_LEN)),
    )

    parser.add_argument(
        "--epochs",
        type=int,
        default=int(os.getenv("EPOCHS", DEFAULT_EPOCHS)),
    )

    parser.add_argument(
        "--batch-size",
        type=int,
        default=int(os.getenv("BATCH_SIZE", DEFAULT_BATCH_SIZE)),
    )

    parser.add_argument(
        "--lr",
        type=float,
        default=float(os.getenv("LR", DEFAULT_LR)),
    )

    parser.add_argument(
        "--weight-decay",
        type=float,
        default=float(os.getenv("WEIGHT_DECAY", DEFAULT_WEIGHT_DECAY)),
    )

    parser.add_argument(
        "--patience",
        type=int,
        default=int(os.getenv("PATIENCE", DEFAULT_PATIENCE)),
    )

    return parser.parse_args()


def main():
    args = parse_args()

    train_model(
        csv_path=Path(args.csv),
        model_out=Path(args.out),
        max_len=args.max_len,
        epochs=args.epochs,
        batch_size=args.batch_size,
        lr=args.lr,
        weight_decay=args.weight_decay,
        patience=args.patience,
    )


if __name__ == "__main__":
    main()