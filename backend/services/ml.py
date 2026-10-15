from __future__ import annotations

import os
from pathlib import Path

import torch
import torch.nn as nn


BASE_DIR = Path(__file__).resolve().parents[2]

MODEL_PATH = os.getenv(
    "MODEL_PATH",
    str(BASE_DIR / "artifacts" / "model.pt"),
)

DEVICE = os.getenv(
    "MODEL_DEVICE",
    "cuda" if torch.cuda.is_available() else "cpu",
)

_bundle = None


def normalize_url_for_cnn(s: str) -> str:
    """
    예측 시 CNN 입력용 전처리.
    학습 때와 동일해야 함.

    중요:
    - 도메인만 자르지 않음
    - path/query 제거 안 함
    - 마스킹 안 함
    """
    v = str(s or "").strip()

    if not v:
        return ""

    v = v.replace("\r", "").replace("\n", "").replace("\t", "")
    v = v.lower()

    return v


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
        x = self.emb(x).transpose(1, 2)

        features = []

        for conv in self.convs:
            c = self.relu(conv(x))
            m = self.pool_max(c).squeeze(-1)
            a = self.pool_avg(c).squeeze(-1)
            features.extend([m, a])

        h = torch.cat(features, dim=1)
        h = self.dropout(h)

        return self.fc(h).squeeze(1)


def _encode_text(text: str, vocab: dict[str, int], max_len: int) -> list[int]:
    arr = [vocab.get(ch, 0) for ch in text[:max_len]]

    if len(arr) < max_len:
        arr += [0] * (max_len - len(arr))

    return arr


def _load_bundle():
    global _bundle

    if _bundle is not None:
        return _bundle

    if not os.path.exists(MODEL_PATH):
        print(f"[ML] model not found: {MODEL_PATH}")
        return None

    try:
        raw = torch.load(MODEL_PATH, map_location=DEVICE, weights_only=False)
    except TypeError:
        raw = torch.load(MODEL_PATH, map_location=DEVICE)

    vocab = raw["vocab"]
    max_len = int(raw.get("max_len", 512))
    emb_dim = int(raw.get("emb_dim", 32))
    channels = int(raw.get("channels", 64))

    model = CharCNN(
        vocab_size=len(vocab),
        emb_dim=emb_dim,
        channels=channels,
    )

    model.load_state_dict(raw["state_dict"])
    model.to(DEVICE)
    model.eval()

    _bundle = {
        "model": model,
        "vocab": vocab,
        "max_len": max_len,
        "version": raw.get("version", "ml_fullurl_dl_v1"),
        "model_type": raw.get("model_type", "charcnn"),
        "input_mode": raw.get("input_mode", "raw_full_url"),
        "model_path": MODEL_PATH,
        "best_auc": raw.get("best_auc"),
    }

    print(f"[ML] loaded model: {MODEL_PATH}")
    print(f"[ML] version: {_bundle['version']}")
    print(f"[ML] input_mode: {_bundle['input_mode']}")

    return _bundle


def ml_predict(features: dict, raw_url: str | None = None):
    bundle = _load_bundle()

    if not bundle:
        return None

    text = normalize_url_for_cnn(raw_url or "")

    if not text:
        return None

    x = torch.tensor(
        [_encode_text(text, bundle["vocab"], bundle["max_len"])],
        dtype=torch.long,
        device=DEVICE,
    )

    with torch.no_grad():
        logits = bundle["model"](x)
        proba = float(torch.sigmoid(logits).item())

    meta = {
        "proba_dl": proba,
        "cnn_input": text,
        "model_path": bundle["model_path"],
        "model_type": bundle["model_type"],
        "input_mode": bundle["input_mode"],
        "best_auc": bundle.get("best_auc"),
    }

    return proba, bundle["version"], meta