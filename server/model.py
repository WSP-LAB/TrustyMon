from enum import Enum
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, DateTime
from sqlalchemy.orm import relationship,backref
from sqlalchemy.sql import func
from datetime import datetime

from database import Base, db_session

class TrustyType(Enum):
    Collected = 0b0000
    Reported  = 0b1000

    TrustedHTML = 0b0001
    TrustedScript = 0b0010
    TrustedScriptUrl = 0b0011

class Trusty(Base):
    __tablename__ = "TRUSTY"

    tr_id = Column(Integer, primary_key = True)
    tr_type = Column(Integer)
    tr_hash = Column(String(48))
    tr_content = Column(Text)
    tr_sample = Column(Text)
    tr_domain = Column(Text)
    tr_loc = Column(Text)
    tr_time = Column(DateTime)

    def __init__(self, type, hash, content, domain, sample, loc):
        self.tr_type = type
        self.tr_hash = hash
        self.tr_content = content
        self.tr_sample = sample
        self.tr_domain = domain
        self.tr_loc = loc
        self.tr_time = datetime.now()

    def get_type(self):
        res = ""
        if self.tr_type & 0b1000:
            res = "(Report) "
        else:
            res = "(Collected) "

        if (self.tr_type & 0b0011) == 0b0001:
            res += "HTML"
        elif (self.tr_type & 0b0011) == 0b0010:
            res += "Script"
        else:
            res += "ScriptURL"
        return res

    def render_loc(self):
        t = self.tr_loc.split("#")
        return '''
        File: {} (Line <b>{}</b>, Column <b>{}</b>)<br>
        Domain: {}
        '''.format(t[2], t[0], t[1], self.tr_domain)

    def delete(self):
        db_session.delete(self)
        db_session.commit()
        return ""

class Report(Base):
    __tablename__ = "REPORT"

    re_id = Column(Integer, primary_key = True)
    re_trusty_tr_id = Column(Integer, ForeignKey("TRUSTY.tr_id"))
    re_type = Column(Integer)
    re_datetime = Column(DateTime)
    re_ip = Column(String(64))
    re_hash = Column(String(48))
    re_content = Column(Text)
    re_sample = Column(Text)
    re_domain = Column(Text)
    re_loc = Column(Text)

    def __init__(self, type, datetime, ip, hash, content, sample, domain, loc):
        self.re_type = type
        self.re_datetime = datetime
        self.re_ip = ip
        self.re_hash = hash
        self.re_content = content
        self.re_sample = sample
        self.re_domain = domain
        self.re_loc = loc
        self.re_trusty_tr_id = 0

    def get_type(self):
        if (self.re_type & 0b0011) == 0b0001:
            return "HTML"
        elif (self.re_type & 0b0011) == 0b0010:
            return "Script"
        else:
            return "ScriptURL"

    def render_loc(self):
        t = self.re_loc.split("#")
        return '''
        File: {} (Line <b>{}</b>, Column <b>{}</b>)<br>
        Domain: {}
        '''.format(t[2], t[0], t[1], self.re_domain)


    def trust(self):
        if self.re_trusty_tr_id != 0:
            return "Already Trusted"

        t = Trusty(self.re_type | 0b1000,
                   self.re_hash,
                   self.re_content,
                   self.re_domain,
                   self.re_sample,
                   self.re_loc)
        db_session.add(t)
        db_session.commit()

        self.re_trusty_tr_id = t.tr_id
        db_session.commit()

        return ""

    def untrust(self):
        if self.re_trusty_tr_id == 0:
            return "Not Trusted yet"
        tr = Trusty.query.filter_by(tr_id = self.re_trusty_tr_id)
        if not tr:
            return "Already untrusted"
        db_session.remove(tr)
        self.re_trusty_tr_id = 0
        db_session.commit()

