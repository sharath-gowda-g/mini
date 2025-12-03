from sqlalchemy import Column, Integer, String, ForeignKey, Float, DateTime
from sqlalchemy.orm import relationship, declarative_base
from datetime import datetime

# Define Base here per new specification
Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    # Column in existing DB is password_hash; support both naming via property.
    password_hash = Column(String, nullable=False)
    role = Column(String, nullable=False, default="user")  # "user" or "admin"

    suspicious_queries = relationship(
        "SuspiciousQuery",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    @property
    def hashed_password(self):  # compatibility alias for older code paths
        return self.password_hash


class SuspiciousQuery(Base):
    __tablename__ = "suspicious_queries"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    qname = Column(String, nullable=False)
    confidence = Column(Float, nullable=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)

    user = relationship("User", back_populates="suspicious_queries")
