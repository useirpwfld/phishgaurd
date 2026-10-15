from sqlalchemy import inspect, text
from db import Base, engine


def ensure_scan_results_columns():
    """
    create_all()은 이미 존재하는 테이블의 누락 컬럼을 자동으로 추가하지 않는다.
    개발 중 기존 DB를 그대로 쓰면 features/model_version/label 컬럼이 없어
    /scan 저장 단계에서 DB 오류가 날 수 있으므로 최소 마이그레이션을 보정한다.
    """
    with engine.begin() as conn:
        inspector = inspect(conn)

        tables = inspector.get_table_names()
        if "scan_results" not in tables:
            return

        cols = {c["name"] for c in inspector.get_columns("scan_results")}

        if "features" not in cols:
            conn.execute(
                text(
                    "ALTER TABLE scan_results "
                    "ADD COLUMN features JSONB NOT NULL DEFAULT '{}'::jsonb"
                )
            )

        if "model_version" not in cols:
            conn.execute(
                text(
                    "ALTER TABLE scan_results "
                    "ADD COLUMN model_version VARCHAR NOT NULL DEFAULT 'rule-v1'"
                )
            )

        if "label" not in cols:
            conn.execute(text("ALTER TABLE scan_results ADD COLUMN label VARCHAR"))

        if "ml_proba" not in cols:
            conn.execute(text("ALTER TABLE scan_results ADD COLUMN ml_proba DOUBLE PRECISION"))

        if "ml_proba_local" not in cols:
            conn.execute(text("ALTER TABLE scan_results ADD COLUMN ml_proba_local DOUBLE PRECISION"))

        if "ml_proba_public" not in cols:
            conn.execute(text("ALTER TABLE scan_results ADD COLUMN ml_proba_public DOUBLE PRECISION"))

        if "reason" in cols:
            conn.execute(text("ALTER TABLE scan_results ALTER COLUMN reason TYPE TEXT"))


def init_db():
    Base.metadata.create_all(bind=engine)
    ensure_scan_results_columns()


def main():
    init_db()
    print("DB tables ready")


if __name__ == "__main__":
    main()
