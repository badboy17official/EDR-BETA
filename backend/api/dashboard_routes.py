from fastapi import APIRouter, Depends, Query
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import func, desc
from typing import Optional

from db.session import get_db_session
from db.models import Reputation, FileMetadata, DynamicFeatures

router = APIRouter()

@router.get("/stats")
async def get_stats(db: AsyncSession = Depends(get_db_session)):
    total = (await db.execute(select(func.count(Reputation.id)))).scalar()
    
    malicious = (await db.execute(
        select(func.count(Reputation.id)).where(Reputation.classification == "malicious")
    )).scalar()
    
    suspicious = (await db.execute(
        select(func.count(Reputation.id)).where(Reputation.classification == "suspicious")
    )).scalar()
    
    benign = (await db.execute(
        select(func.count(Reputation.id)).where(Reputation.classification == "benign")
    )).scalar()
    
    return {
        "status": "success",
        "data": {
            "total_scans": total,
            "malicious": malicious,
            "suspicious": suspicious,
            "benign": benign
        }
    }

@router.get("/reports")
async def get_reports(
    skip: int = 0, 
    limit: int = 50, 
    classification: Optional[str] = None,
    search: Optional[str] = None,
    db: AsyncSession = Depends(get_db_session)
):
    query = select(Reputation).order_by(desc(Reputation.last_seen))
    
    if classification:
        query = query.where(Reputation.classification == classification)
    if search:
        query = query.where(Reputation.sha256.ilike(f"%{search}%"))
        
    query = query.offset(skip).limit(limit)
    res = await db.execute(query)
    reputations = res.scalars().all()
    
    results = []
    for r in reputations:
        # Get dynamic features if available
        dyn_query = select(DynamicFeatures).where(DynamicFeatures.sha256 == r.sha256).order_by(desc(DynamicFeatures.created_at)).limit(1)
        dyn_res = await db.execute(dyn_query)
        dyn = dyn_res.scalars().first()
        
        dyn_data = None
        if dyn:
            import json
            dyn_data = {
                "dynamic_risk": dyn.risk_score,
                "network_activity": dyn.network_activity,
                "suspicious_actions": json.loads(dyn.suspicious_actions) if dyn.suspicious_actions else [],
            }
            
        results.append({
            "sha256": r.sha256,
            "classification": r.classification,
            "is_malicious": r.is_malicious,
            "risk_score": r.risk_score,
            "confidence_score": r.confidence_score,
            "first_seen": r.first_seen.isoformat() if r.first_seen else None,
            "last_seen": r.last_seen.isoformat() if r.last_seen else None,
            "sandbox_results": dyn_data
        })
        
    return {
        "status": "success",
        "data": results
    }
