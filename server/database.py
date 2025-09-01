from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base

import config
engine = create_engine(config.SQLITE_DB, pool_size=100, max_overflow=0)
db_session = scoped_session(sessionmaker(bind = engine, autocommit = False, autoflush = False))

Base = declarative_base()
Base.query = db_session.query_property()
