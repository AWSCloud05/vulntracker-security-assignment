from sqlalchemy import create_engine, or_
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from config import DATABASE_URL

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def search_scans_by_query(db, query: str) -> list:
    """Search scan records using SQLAlchemy parameterized ORM filters."""
    import models

    search_pattern = f"%{query}%"

    results = (
        db.query(models.ScanResult)
        .filter(
            or_(
                models.ScanResult.title.ilike(search_pattern),
                models.ScanResult.description.ilike(search_pattern),
                models.ScanResult.cve_id.ilike(search_pattern),
            )
        )
        .all()
    )

    return [
        {
            "id": scan.id,
            "title": scan.title,
            "description": scan.description,
            "severity": scan.severity,
            "status": scan.status,
            "cve_id": scan.cve_id,
            "affected_component": scan.affected_component,
            "owner_id": scan.owner_id,
            "created_at": scan.created_at,
        }
        for scan in results
    ]
