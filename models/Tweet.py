from datetime import datetime
from db import db

class Tweet(db.Model):
    __tablename__ = "tweets"

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(280), nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    def __init__(self, content, user_id):
        self.content = content
        self.user_id = user_id

    def json(self): 
        return {
            "id": self.id,
            "content": self.content,
            "timestamp": self.timestamp,
            "user_id": self.user_id
        }

    @classmethod
    def find_by_id(cls, _id):
        return cls.query.filter_by(id=_id).first()

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    def delete_from_db(self):
        db.session.delete(self)
        db.session.commit()