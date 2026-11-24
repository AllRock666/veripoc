"""SQLAlchemy store. SQLite by default; set DATABASE_URL=postgresql+psycopg2://... for PostgreSQL."""
import json, os
from sqlalchemy import create_engine, Column, Integer, String, Float, Text, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()


class FindingRow(Base):
    __tablename__ = "findings"
    id = Column(Integer, primary_key=True)
    dedupe_key = Column(String, unique=True, index=True)
    payload = Column(Text)
    verdict = Column(String, default="PENDING")
    reason = Column(Text, default="")


class AttemptRow(Base):
    __tablename__ = "attempts"
    id = Column(Integer, primary_key=True)
    finding_id = Column(Integer, ForeignKey("findings.id"), index=True)
    n = Column(Integer)
    script = Column(Text)
    exit_code = Column(Integer)
    stdout = Column(Text)
    stderr = Column(Text)
    duration_s = Column(Float)
    verdict = Column(String)
    tokens = Column(Integer, default=0)


def get_session(url: str | None = None):
    engine = create_engine(url or os.getenv("DATABASE_URL", "sqlite:///verifier.db"))
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def upsert_finding(s, f) -> FindingRow:
    key = json.dumps(f.dedupe_key)
    row = s.query(FindingRow).filter_by(dedupe_key=key).first()
    if not row:
        row = FindingRow(dedupe_key=key, payload=f.model_dump_json())
        s.add(row); s.commit()
    return row
