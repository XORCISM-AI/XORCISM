"""
xticket.py — Models of the XTICKET database (ticketing / helpdesk tool).

Tables:
  TICKET            — a ticket (status, priority, severity, requester, assignee, dates)
  TICKETCOMMENT     — a comment / activity on a ticket (internal or public)
  TICKETCATEGORY    — ticket category
  TICKETATTACHMENT  — a ticket attachment

ISOLATED MetaData: a TICKET table already exists in XORCISM.db under the shared Base
(xorcism.py). XTICKET therefore has its own declarative base; the routing to the database
happens via session_scope('XTICKET').
"""
from sqlalchemy import Column, Integer, Text
from sqlalchemy.orm import DeclarativeBase


class TicketBase(DeclarativeBase):
    pass


class TICKET(TicketBase):
    __tablename__ = 'TICKET'
    __bind_key__ = 'XTICKET'

    TicketID = Column(Integer, primary_key=True)
    TicketGUID = Column(Text)
    TicketNumber = Column(Text)
    Subject = Column(Text)
    Description = Column(Text)
    Status = Column(Text)               # Open / In Progress / On Hold / Resolved / Closed / Cancelled
    Priority = Column(Text)             # Low / Medium / High / Urgent
    Severity = Column(Text)            # S1-Critical / S2-High / S3-Medium / S4-Low
    TicketType = Column(Text)           # Incident / Service Request / Problem / Change / Question
    CategoryID = Column(Integer)        # -> TICKETCATEGORY
    RequesterName = Column(Text)
    RequesterEmail = Column(Text)
    AssigneeName = Column(Text)
    Tags = Column(Text)
    CreatedDate = Column(Text)
    UpdatedDate = Column(Text)
    DueDate = Column(Text)              # date
    ResolvedDate = Column(Text)         # date
    ClosedDate = Column(Text)           # date
    Resolution = Column(Text)

    def __repr__(self):
        return f'<TICKET {self.TicketID}>'


class TICKETCOMMENT(TicketBase):
    __tablename__ = 'TICKETCOMMENT'
    __bind_key__ = 'XTICKET'

    TicketCommentID = Column(Integer, primary_key=True)
    TicketCommentGUID = Column(Text)
    TicketID = Column(Integer)
    Author = Column(Text)
    Body = Column(Text)
    IsInternal = Column(Integer)        # 1 = note interne, 0 = visible demandeur
    CreatedDate = Column(Text)

    def __repr__(self):
        return f'<TICKETCOMMENT {self.TicketCommentID}>'


class TICKETCATEGORY(TicketBase):
    __tablename__ = 'TICKETCATEGORY'
    __bind_key__ = 'XTICKET'

    TicketCategoryID = Column(Integer, primary_key=True)
    TicketCategoryName = Column(Text)
    Description = Column(Text)
    CreatedDate = Column(Text)

    def __repr__(self):
        return f'<TICKETCATEGORY {self.TicketCategoryID}>'


class TICKETATTACHMENT(TicketBase):
    __tablename__ = 'TICKETATTACHMENT'
    __bind_key__ = 'XTICKET'

    TicketAttachmentID = Column(Integer, primary_key=True)
    TicketID = Column(Integer)
    FileName = Column(Text)
    FilePath = Column(Text)
    CreatedDate = Column(Text)

    def __repr__(self):
        return f'<TICKETATTACHMENT {self.TicketAttachmentID}>'
