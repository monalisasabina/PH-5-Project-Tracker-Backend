
import random
import string
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import datetime
from sqlalchemy.exc import IntegrityError
from flask_mail import Mail, Message
from sqlalchemy_serializer import SerializerMixin
from dotenv import load_dotenv
load_dotenv()

import os


db =SQLAlchemy()
bcrypt=Bcrypt()
mail=Mail()



# User Model for Authentication
class User(db.Model, SerializerMixin):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)  # True for admin, False for student
    is_admin = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)  # Field to track verification status
    verification_code = db.Column(db.String(6), nullable=True)  # Field to store verification code
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    role = db.Column(db.String(20), nullable=False)

    # relationship between user"owner" and project
    projects = db.relationship('Project', back_populates='owner',passive_deletes=True)
    

    # Serialization rules: excluding sensitive fields
    serialize_rules = ('-password', '-verification_code','-projects',)

    def __repr__(self):
        return f"<User {self.username} (Admin: {self.is_admin}, Verified: {self.is_verified}), Verification_code: {self.verification_code}>"


    # For authentication(important)
    def set_password_hash(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password_hash(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)
    

    # Generate a random 6-digit verification code
    def generate_verification_code(self):
        code = ''.join(random.choices(string.digits, k=6))
        self.verification_code = code
        try:
           db.session.add(self)
           db.session.commit()
           print(f"Code committed to database: {self.verification_code}")
        except Exception as e:
           print(f"Error committing verification code to database: {e}")
        return code


    # Validate email format
    @staticmethod
    def validate_email(email):
        if '@' not in email:
            raise ValueError("Invalid email format.")

    # Validate username and password, and send verification code
    def validate_and_send_code(self):
        if len(self.username) < 3:
            raise ValueError("Username must be at least 3 characters long.")
        if len(self.password) < 6:
            raise ValueError("Password must be at least 6 characters long.")
        self.validate_email(self.email)
        
        # Generate and send verification code
        code = self.generate_verification_code()
        send_verification_email(self.email, code)

    # Verify code entered by user
    def verify_user(self, code_entered):
        if self.verification_code == code_entered:
            self.is_verified = True
            self.verification_code = None  # Clear the code after successful verification
            db.session.commit()
            return True
        return False


# Function to send the verification email
def send_verification_email(recipient_email, code):

    try:
        msg = Message(
            subject="Your Verification Code",
            sender=os.getenv('MAIL_USERNAME'),  # Replace with your actual sender email
            recipients=[recipient_email],
            body=f"Your verification code is: {code}"
        )
        print(f"Sending verification code {code} to {recipient_email}")
        mail.send(msg)
    except Exception as e:
        print(f"Error sending email: {e}")


# Project Model
class Project(db.Model, SerializerMixin):
    __tablename__ = 'projects'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    github_url = db.Column(db.String(200), nullable=False)
    type = db.Column(db.String(50), nullable=False)  # project type
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    image_url = db.Column(db.String(255), nullable=True)  # New column for optional image URl
    
    # Foreign Keys
    user_id=db.Column(db.Integer, db.ForeignKey('users.id'),nullable=False)
    cohort_id = db.Column(db.Integer, db.ForeignKey('cohorts.id', ondelete='SET NULL'), nullable=True)


    # Relationships
    owner =db.relationship('User', back_populates='projects')
    cohort = db.relationship('Cohort', back_populates='projects')
    members = db.relationship(
        'ProjectMember',
        back_populates='project',  # Explicitly defining bidirectional relationship
        passive_deletes=True  #allows to delete user
    )

    #serialize
    # serialize_rules = ('-owner.projects', '-members.project', '-cohort.projects', '-members.cohort',)
    serialize_rules = ('-members',)

    def __repr__(self):
        # iterate over project member names
        member_names = [member.name for member in self.members]

        return f"<Project {self.name} owner_id: {self.user_id} owner: {self.owner.username}  " +\
        f"project_members: {','.join(member_names)}>"

    # Validators
    def validate(self):
        if len(self.name) < 3:
            raise ValueError("Project name must be at least 3 characters long.")
        if len(self.description) < 10:
            raise ValueError("Description must be at least 10 characters long.")
        if not self.github_url.startswith('http'):
            raise ValueError("Invalid GitHub URL format.")


# Cohort Model
class Cohort(db.Model, SerializerMixin):
    __tablename__ = 'cohorts'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(50), nullable=False)
    github_url = db.Column(db.String(50), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    start_date = db.Column(db.DateTime, default=datetime.utcnow)
    end_date = db.Column(db.String, nullable=False)

    # Relationship with Project
    projects = db.relationship(
        'Project',
        back_populates='cohort',
    )

    members = db.relationship(
        'ProjectMember',
        back_populates='cohort',
    )

    serialize_rules = ('-projects.cohort', '-members.cohort', '-projects.members', '-members.project')  # Prevent recursive nesting

    def __repr__(self):
        return f"<Cohort {self.name} (Type: {self.type})>"
    

    # Validators
    def validate(self):
        if len(self.name) < 3:
            raise ValueError("Cohort name must be at least 3 characters long.")
        if not self.github_url.startswith('http'):
            raise ValueError("Invalid GitHub URL format.")




# ProjectMember Model - Join table for Many-to-Many relationship between Projects and Users
class ProjectMember(db.Model, SerializerMixin):
    __tablename__ = 'project_members'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id', ondelete='CASCADE'), nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    role = db.Column(db.String(50))  # e.g., 'Developer', 'Lead', 'Reviewer'

    # Foreign key
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'),nullable=False) 
    cohort_id = db.Column(db.Integer, db.ForeignKey('cohorts.id'), nullable=True)

    # Relationships
    project = db.relationship('Project', back_populates='members')  # Using back_populates
    cohort = db.relationship('Cohort', back_populates='members') 

    # serialize_rules = ('-project.members','-cohort.members',)
    serialize_rules = ('-members',) 

    def __repr__(self):
        return f"<ProjectMember (Project ID: {self.project_id}, User ID: {self.user_id}, Role: {self.role})>"
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'project_id': self.project_id,
            'joined_at': self.joined_at.isoformat() if self.joined_at else None,
            'role': self.role,
            'user_id': self.user_id,
            'cohort_id': self.cohort_id
        }
    

    # Validators
    def validate(self):
        if len(self.role) < 3:
            raise ValueError("Role must be at least 3 characters long.")


# Integrity error handler decorator
def handle_integrity_error(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except IntegrityError as e:
            db.session.rollback()  # Rollback in case of error
            raise ValueError("Integrity error: Something went wrong with the database.")
    return wrapper


# Example usage for validation before adding or updating
@handle_integrity_error
def add_user(user):
    user.validate_and_send_code()  # Validate and send code during user registration
    db.session.add(user)
    db.session.commit()