from datetime import datetime, timezone, timedelta
from time import time
from sqlalchemy import String, Integer, ForeignKey, Boolean, Interval, UniqueConstraint, or_, and_
from sqlalchemy import inspect, event
from sqlalchemy.orm import Mapped, WriteOnlyMapped, mapped_column, relationship
from typing import List, Optional
from pySMC import db, login, app
from flask_login import UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from config import Config
import pytz


class Base(db.Model):
    __abstract__ = True


class TrackTimeMixin:
    created_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        data = {
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }
        return data


class TrackUserMixin:
    created_by_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), index=True)
    updated_by_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), index=True)


class TrackTimeUserMixin(TrackTimeMixin, TrackUserMixin):
    pass


class EnabledMixin:
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    @property
    def status(self):
        return "Enabled" if self.is_enabled else "Disabled"


class DisabledMixin:
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    @property
    def status(self):
        return "Enabled" if self.is_enabled else "Disabled"


class SoftDeleteMixin:
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    deleted_at: Mapped[datetime] = mapped_column(nullable=True)
    deleted_by_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), index=True)

    def soft_delete(self):
        self.is_deleted = True
        self.deleted_at = datetime.now(timezone.utc)
        if current_user:
            self.deleted_by_id = current_user.id

 
class User(Base, UserMixin, EnabledMixin, TrackTimeUserMixin):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    first_name: Mapped[str] = mapped_column(String(50))
    last_name: Mapped[str] = mapped_column(String(50))
    last_seen: Mapped[Optional[datetime]] = mapped_column(default=lambda: datetime.now(timezone.utc))

    roles: Mapped[List["Role"]] = relationship(
        "Role",
        secondary="user_role",
        back_populates="users",
        primaryjoin="and_(User.id == UserRole.user_id, UserRole.is_enabled == True)",
        secondaryjoin="and_(Role.id == UserRole.role_id, UserRole.is_enabled == True, Role.is_enabled == True)",
        viewonly=True
    )

    user_roles: Mapped[List["UserRole"]] = relationship(
        back_populates="user",
        foreign_keys="[UserRole.user_id]"
    )
    
    def __str__(self):
        return self.username

    def __repr__(self) -> str:
        return f'<User: {self.username}>'

    def __init__(self, username, email, first_name, last_name):
        self.username = username
        self.email = email
        self.first_name = first_name
        self.last_name = last_name

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email
        }

    def full_name(self) -> str:
        return f"{self.first_name} {self.last_name}"

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_reset_password_token(self, expires_in=600):
        return jwt.encode(
            {'reset_password': self.id, 'exp': time() + expires_in},
            app.config['SECRET_KEY'], algorithm='HS256')

    @classmethod
    def find_by_username(cls, session, username: str) -> "User":
        return session.query(cls).filter_by(username=username).first()

    @classmethod
    def find_by_email(cls, session, email: str) -> "User":
        return session.query(cls).filter_by(email=email).first()

    def get_roles(self) -> List["Role"]:
        return self.roles

    def has_role(self, role_name: str) -> bool:
        return any(role.name == role_name for role in self.roles)

    @staticmethod
    def verify_reset_password_token(token):
        try:
            id_ = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])['reset_password']
        except:
            return
        return db.session.get(User, id_)

    def get_allowed_status_id_with_direction(self):
        user_roles = (
            db.session.query(Role.id)
            .join(UserRole, UserRole.role_id == Role.id)
            .filter(UserRole.user_id == self.id)
            .filter(UserRole.is_enabled == True)
            .filter(Role.is_enabled == True)
            .subquery()
        )

        user_roles_select = db.session.query(user_roles.c.id)

        forward_status = (
            db.session.query(Status.id)
            .join(Transition, Transition.previous_status_id == Status.id)
            .join(TransitionRole, TransitionRole.transition_id == Transition.id)
            .filter(TransitionRole.role_id.in_(user_roles_select))
            .filter(Status.is_enabled == True)
            .filter(Transition.is_enabled == True)
            .filter(TransitionRole.is_enabled == True)
            .filter(Transition.allow_forward == True)
            .distinct()
            .all()
        )

        backward_status = (
            db.session.query(Status.id)
            .join(Transition, Transition.following_status_id == Status.id)
            .join(TransitionRole, TransitionRole.transition_id == Transition.id)
            .filter(TransitionRole.role_id.in_(user_roles_select))
            .filter(Status.is_enabled == True)
            .filter(Transition.is_enabled == True)
            .filter(TransitionRole.is_enabled == True)
            .filter(Transition.allow_backward == True)
            .distinct()
            .all()
        )

        forward_statuses = [status.id for status in forward_status]
        backward_statuses = [status.id for status in backward_status]

        return {
            "forward": forward_statuses,
            "backward": backward_statuses,
            "both": forward_statuses + list(set(backward_statuses) - set(forward_statuses))
        }


class Role(Base, EnabledMixin, TrackTimeUserMixin):
    __tablename__ = "roles"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(String(200))

    users: Mapped[List["User"]] = relationship(
        "User",
        secondary="user_role",
        back_populates="roles",
        primaryjoin="and_(Role.id == UserRole.role_id, UserRole.is_enabled == True, Role.is_enabled == True)",
        secondaryjoin="and_(User.id == UserRole.user_id, UserRole.is_enabled == True)",
        viewonly=True
    )

    role_users: Mapped[List["UserRole"]] = relationship(
        back_populates="role",
        foreign_keys="[UserRole.role_id]"
    )

    role_transitions: Mapped[List["TransitionRole"]] = relationship(
        back_populates="role",
        foreign_keys="[TransitionRole.role_id]"
    )

    def __init__(self, name, description):
        self.name = name
        self.description = description

    def __str__(self):
        return self.name

    def __repr__(self) -> str:
        return f'<Role: {self.name}>'

    @classmethod
    def find_by_name(cls, session, name: str) -> "Role":
        return session.query(cls).filter_by(name=name).first()


class UserRole(Base, EnabledMixin, TrackTimeUserMixin):
    __tablename__ = "user_role"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    role_id: Mapped[int] = mapped_column(Integer, ForeignKey("roles.id"), nullable=False)
 
    __table_args__ = (
        UniqueConstraint('user_id', 'role_id', name='unique_user_role'),
    ) 

    user: Mapped["User"] = relationship(
        back_populates="user_roles",
        foreign_keys=[user_id]
    )
    role: Mapped["Role"] = relationship(
        back_populates="role_users",
        foreign_keys=[role_id]
    )

    def __init__(self, user_id, role_id):
        self.user_id = user_id
        self.role_id = role_id

    def get_username(self):
        user = User.query.get(self.user_id)
        return user.username if user else None

    def get_role(self):
        role = Role.query.get(self.role_id)
        return role.name if role else None

    def to_dict(self):
        return {
            'user_id': self.user_id,
            'role_id': self.role_id,
            'is_enabled': self.is_enabled,
            'username': self.get_username()
        }


class LineType(Base, EnabledMixin, TrackTimeUserMixin):
    __tablename__ = "line_type"
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    description: Mapped[str] = mapped_column(nullable=True)
    lines: WriteOnlyMapped['Line'] = relationship(back_populates='line_type', foreign_keys='Line.type_id')

    def __init__(self, description):
        self.description = description

    def __str__(self):
        return self.description

    def __repr__(self) -> str:
        return f'<LineType: {self.description}>'

    def to_dict(self):
        return {
            'id': self.id,
            'description': self.description
        }


class Line(Base, EnabledMixin, TrackTimeUserMixin):
    __tablename__ = "line"
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    description: Mapped[str] = mapped_column(nullable=True)
    type_id: Mapped[int] = mapped_column(ForeignKey('line_type.id'), index=True)

    jobs: WriteOnlyMapped['Job'] = relationship(back_populates='line', foreign_keys='Job.line_id')
    line_type: Mapped[LineType] = relationship(back_populates='lines', foreign_keys=[type_id])

    def __init__(self, description, type_id):
        self.description = description
        self.type_id = type_id

    def __str__(self):
        return self.description

    def __repr__(self) -> str:
        return f'<Line: {self.description}>'

    def to_dict(self):
        return {
            'id': self.id,
            'description': self.description,
            'type_id': self.type_id
        }


class Status(Base, DisabledMixin, TrackTimeUserMixin):
    __tablename__ = "statuses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    status: Mapped[int] = mapped_column(Integer, nullable=False)
    state: Mapped[str] = mapped_column(String, nullable=False)

    jobs: WriteOnlyMapped['Job'] = relationship(back_populates='status', foreign_keys='Job.status_id')
    previous_statuses: Mapped[List["Status"]] = relationship(
        "Status",
        secondary="transitions",
        primaryjoin="and_(Status.id == Transition.following_status_id, Transition.allow_backward == True, Transition.is_enabled == True, Status.is_enabled == True)",
        secondaryjoin="and_(Status.id == Transition.previous_status_id, Transition.is_enabled == True, Status.is_enabled == True)",
        viewonly=True
    )
    following_statuses: Mapped[List["Status"]] = relationship(
        "Status",
        secondary="transitions",
        primaryjoin="and_(Status.id == Transition.previous_status_id, Transition.allow_forward == True, Transition.is_enabled == True, Status.is_enabled == True)",
        secondaryjoin="and_(Status.id == Transition.following_status_id, Transition.is_enabled == True, Status.is_enabled == True)",
        viewonly=True
    )
    prev_transitions: Mapped[List["Transition"]] = relationship(
        "Transition",
        foreign_keys="[Transition.previous_status_id]",
        back_populates="previous_status"
    )
    foll_transitions: Mapped[List["Transition"]] = relationship(
        "Transition",
        foreign_keys="[Transition.following_status_id]",
        back_populates="following_status"
    )

    def __init__(self, status, state, is_enabled=False):
        self.status = status
        self.state = state
        self.is_enabled = is_enabled

    def __str__(self):
        return f'{self.status} - {self.state}'

    def __repr__(self) -> str:
        return f'<State: {self.state}>'

    def to_dict(self):
        return {
            'id': self.id,
            'status': self.status,
            'state': self.state,
            'is_enabled': self.is_enabled,
            'previous_statuses': [status.to_dict() for status in self.previous_statuses if status.is_enabled],
            'following_statuses': [status.to_dict() for status in self.following_statuses if status.is_enabled]
        }


class Transition(Base, DisabledMixin, TrackTimeUserMixin):
    __tablename__ = "transitions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    previous_status_id: Mapped[int] = mapped_column(Integer, ForeignKey("statuses.id"), nullable=False)
    following_status_id: Mapped[int] = mapped_column(Integer, ForeignKey("statuses.id"), nullable=False)
    allow_backward: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    allow_forward: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    __table_args__ = (
        UniqueConstraint('previous_status_id', 'following_status_id', name='unique_transition'),
    )

    previous_status: Mapped["Status"] = relationship(
        "Status",
        foreign_keys=[previous_status_id],
        back_populates="prev_transitions",
        overlaps="following_statuses,previous_statuses"
    )
    following_status: Mapped["Status"] = relationship(
        "Status",
        foreign_keys=[following_status_id],
        back_populates="foll_transitions",
        overlaps="following_statuses,previous_statuses"
    )

    transition_roles: Mapped[List["TransitionRole"]] = relationship(
        back_populates="transition",
        foreign_keys="[TransitionRole.transition_id]"
    )

    def __init__(self, previous_status_id, following_status_id, allow_backward=True, allow_forward=True, is_enabled=False):
        self.previous_status_id = previous_status_id
        self.following_status_id = following_status_id
        self.allow_backward = allow_backward
        self.allow_forward = allow_forward
        self.is_enabled = is_enabled

    def get_previous_state(self):
        status = Status.query.get(self.previous_status_id)
        return status.id if status else None

    def get_following_state(self):
        status = Status.query.get(self.following_status_id)
        return status.id if status else None

    def __str__(self):
        return f'{str(Status.query.get(self.previous_status_id))} {"<" if self.allow_backward else ""}{">" if self.allow_forward else ""} {str(Status.query.get(self.following_status_id))}'

    def __repr__(self):
        return f'Transition(id={self.id}, previous_status_id={self.previous_status_id}, following_status_id={self.following_status_id}, allow_backward={self.allow_backward}, allow_forward={self.allow_forward}, is_enabled={self.is_enabled})'

    def to_dict(self):
        return {
            "id": self.id,
            "previous_status_id": self.previous_status_id,
            "following_status_id": self.following_status_id,
            "allow_backward": self.allow_backward,
            "allow_forward": self.allow_forward,
            "is_enabled": self.is_enabled,
        }


class TransitionRole(Base, DisabledMixin, TrackTimeUserMixin):
    __tablename__ = "transition_roles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    transition_id: Mapped[int] = mapped_column(Integer, ForeignKey("transitions.id"), nullable=False)
    role_id: Mapped[int] = mapped_column(Integer, ForeignKey("roles.id"), nullable=False)
 
    __table_args__ = (
        UniqueConstraint('transition_id', 'role_id', name='unique_transition_role'),
    ) 

    transition: Mapped["Transition"] = relationship(
        back_populates="transition_roles",
        foreign_keys=[transition_id]
    )
    role: Mapped["Role"] = relationship(
        back_populates="role_transitions",
        foreign_keys=[role_id]
    )

    def __init__(self, transition_id, role_id, is_enabled=False):
        self.transition_id = transition_id
        self.role_id = role_id
        self.is_enabled = is_enabled

    def to_dict(self):
        return {
            'transition_id': self.transition_id,
            'role_id': self.role_id,
            'is_enabled': self.is_enabled,
        }


class Activity(Base, TrackTimeUserMixin):
    __tablename__ = "activities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    description: Mapped[int] = mapped_column(Integer)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class Job(Base, TrackTimeUserMixin):
    """
    Represents a job in the system with its associated properties and relationships.
    """
    __tablename__ = "job"

    # Core fields
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    wo: Mapped[int] = mapped_column(index=True, nullable=True)
    batch: Mapped[str] = mapped_column(index=True, nullable=True)

    # Foreign keys and relationships
    line_id: Mapped[int] = mapped_column(Integer, ForeignKey('line.id'), index=True)
    line: Mapped['Line'] = relationship(back_populates='jobs', foreign_keys=[line_id])
    status_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("statuses.id"),
        index=True,
        default=1,
        nullable=False
    )
    status: Mapped['Status'] = relationship(back_populates='jobs', foreign_keys=[status_id])

    # Scheduling fields
    planned_date: Mapped[datetime] = mapped_column(nullable=True)
    duration: Mapped[timedelta] = mapped_column(Interval, nullable=True)
    prio_date: Mapped[datetime] = mapped_column(nullable=True)

    # Quantity fields
    planned_qty: Mapped[int] = mapped_column(nullable=True)
    exact_qty: Mapped[bool] = mapped_column(default=False)
    remaining_qty: Mapped[bool] = mapped_column(default=False)

    # Product fields
    is_pq: Mapped[bool] = mapped_column(default=False)
    product_type_id: Mapped[Optional[int]] = mapped_column(nullable=True)
    item: Mapped[str] = mapped_column(nullable=True)
    description: Mapped[str] = mapped_column(nullable=True)
    setup: Mapped[str] = mapped_column(nullable=True)

    def __str__(self) -> str:
        return f'{self.batch} (WO{self.wo})'

    def __repr__(self) -> str:
        return f'<Job: {self.batch} (WO{self.wo})>'

    def to_dict(self) -> dict:
        """
        Converts the Job instance to a dictionary format suitable for JSON serialization.
        """
        return {
            'id': self.id,
            'line_id': self.line_id,
            'line': self.line.description,
            'wo': self.wo,
            'batch': self.batch,
            'status_id': self.status_id,
            'status': self.status.status,
            'state': self.status.state,
            'planned_date': self._format_datetime(self.planned_date),
            'duration': self._format_timedelta(self.duration),
            'planned_qty': self.planned_qty,
            'exact_qty': self.exact_qty,
            'remaining_qty': self.remaining_qty,
            'is_pq': self.is_pq,
            'product_type_id': self.product_type_id,
            'item': self.item,
            'description': self.description,
            'setup': self.setup,
            'prio_date': self._format_datetime(self.prio_date)
        }

    @staticmethod
    def _format_datetime(dt: Optional[datetime]) -> Optional[str]:
        """
        Formats a datetime object to string with proper timezone handling.
        """
        if not dt:
            return None
        return dt.replace(
            tzinfo=pytz.timezone('UTC')
        ).astimezone(
            pytz.timezone(Config.LOCAL_TIMEZONE)
        ).strftime('%d/%m/%Y %H:%M:%S')

    @staticmethod
    def _format_timedelta(td: Optional[timedelta]) -> Optional[str]:
        """
        Formats a timedelta object to a human-readable string.
        """
        if not isinstance(td, timedelta):
            return None

        days = td.days
        hours, remainder = divmod(td.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)

        if days:
            day_str = "day" if days == 1 else "days"
            return f"{days} {day_str} {hours:02d}:{minutes:02d}:{seconds:02d}"
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


@event.listens_for(TrackUserMixin, 'before_insert', propagate=True)
def set_created_and_updated(mapper, connection, target):
    if current_user and current_user.is_authenticated:
        target.created_by_id = current_user.id
        target.updated_by_id = current_user.id


@event.listens_for(TrackUserMixin, 'before_update', propagate=True)
def set_updated(mapper, connection, target):
    state = inspect(target)
    
    # Check if the target has a last_seen attribute
    if hasattr(target, 'last_seen'):
        last_seen_hist = state.attrs.last_seen.history

        # Check if last_seen is the only field that has changes
        if last_seen_hist.has_changes() and all(
            not attr.history.has_changes() for attr in state.attrs.values() if attr.key != 'last_seen'
        ):
            return

    if current_user and current_user.is_authenticated:
        target.updated_by_id = current_user.id


@event.listens_for(TrackTimeMixin, 'before_update', propagate=True)
def set_updated(mapper, connection, target):
    state = inspect(target)
    
    # Check if the target has a last_seen attribute
    if hasattr(target, 'last_seen'):
        last_seen_hist = state.attrs.last_seen.history

        # Check if last_seen is the only field that has changes
        if last_seen_hist.has_changes() and all(
            not attr.history.has_changes() for attr in state.attrs.values() if attr.key != 'last_seen'
        ):
            return

    target.updated_at = datetime.now(timezone.utc)


@login.user_loader
def load_user(id_):
    return db.session.get(User, int(id_))
