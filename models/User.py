from db import db
from models.Tweet import Tweet

# followers association table for n:m relationship between users
followers = db.Table('followers',
    db.Column('follower_id', db.Integer, db.ForeignKey('users.id')),
    db.Column('followed_id', db.Integer, db.ForeignKey('users.id'))
)

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, index=True, nullable=False)
    email = db.Column(db.String(120), unique=True, index=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    tweets = db.relationship('Tweet', backref='user', lazy='dynamic')
    followed = db.relationship('User', secondary=followers, primaryjoin=(followers.c.follower_id == id), secondaryjoin=(followers.c.followed_id == id), backref=db.backref('followers', lazy='dynamic'), lazy='dynamic')

    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = password

    def follow(self, user):
        if not self.is_following(user):
            self.followed.append(user)

    def unfollow(self, user):
        if self.is_following(user):
            self.followed.remove(user)

    def is_following(self, user):
        return self.followed.filter(
            followers.c.followed_id == user.id
        ).count() > 0

    def followed_tweets(self):
        followed = Tweet.query.join(
            followers, (followers.c.followed_id == Tweet.user_id)).filter(
                followers.c.follower_id == self.id)
        own = Tweet.query.filter_by(user_id=self.id)
        return followed.union(own).order_by(Tweet.timestamp.desc())

    @classmethod
    def find_by_username(cls, username):
        return cls.query.filter_by(username=username).first()
        
    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    # probably won't use a lot
    def delete_from_db(self):
        db.session.delete(self)
        db.session.commit()