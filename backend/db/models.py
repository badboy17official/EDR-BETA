import enum
from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, Text, Enum
from sqlalchemy.orm import declarative_base
from datetime import datetime

Base = declarative_base()

class TaskStatus(str, enum.Enum):
    PENDING = "PENDING"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

class FileMetadata(Base):
    __tablename__ = "file_metadata"
    
    id = Column(Integer, primary_key=True, index=True)
    sha256 = Column(String(64), unique=True, index=True, nullable=False)
    size = Column(Integer)
    mime_type = Column(String(50))
    first_seen = Column(DateTime, default=datetime.utcnow)
    task_id = Column(String(36), index=True) # Last Sandbox/ML scan execution UUID
    status = Column(Enum(TaskStatus), default=TaskStatus.PENDING)
    agent_id = Column(String(50), index=True)

class Reputation(Base):
    __tablename__ = "reputation"
    
    id = Column(Integer, primary_key=True, index=True)
    sha256 = Column(String(64), unique=True, index=True, nullable=False)
    
    # Binary status
    is_malicious = Column(Boolean, default=False)

    # Tri-state label: benign, suspicious, malicious
    classification = Column(String(16), default="benign")

    # Raw model output 0-100
    risk_score = Column(Float, default=0.0)
    
    # Scoring 0 - 100
    confidence_score = Column(Float, default=0.0) 
    
    # Reputation Context
    frequency = Column(Integer, default=1)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    
    # e.g., ["Ransomware", "Trojan", "CoinMiner"]
    tags = Column(Text, nullable=True)

class StaticFeatures(Base):
    __tablename__ = "static_features"
    
    id = Column(Integer, primary_key=True, index=True)
    task_id = Column(String(36), unique=True, index=True, nullable=False)
    sha256 = Column(String(64), index=True, nullable=False)
    
    file_type = Column(String(20)) # PE, ELF, UNKNOWN
    entropy = Column(Float)
    imports_count = Column(Integer)
    strings_count = Column(Integer)
    
    # Store extracted attributes as JSON text representation (e.g. list of imports)
    raw_data = Column(Text, nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)

class DynamicFeatures(Base):
    __tablename__ = "dynamic_features"
    
    id = Column(Integer, primary_key=True, index=True)
    task_id = Column(String(36), unique=True, index=True, nullable=False)
    sha256 = Column(String(64), index=True, nullable=False)
    
    risk_score = Column(Float, default=0.0)
    network_activity = Column(Boolean, default=False)
    suspicious_actions = Column(Text, nullable=True) # JSON list
    syscalls = Column(Text, nullable=True) # JSON dict
    
    created_at = Column(DateTime, default=datetime.utcnow)
 
