import re
from datetime import datetime, timedelta

from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from wtforms import StringField, SelectField, IntegerField, PasswordField, BooleanField, DateTimeField, SubmitField
from pySMC.custom_fields import DurationField
from wtforms.validators import ValidationError, InputRequired, DataRequired, Regexp, Email, EqualTo, NumberRange, Optional
import sqlalchemy as sa
from pySMC import db
from pySMC.models import User, Line


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = db.session.scalar(sa.select(User).where(
            User.username == username.data))
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        user = db.session.scalar(sa.select(User).where(
            User.email == email.data))
        if user is not None:
            raise ValidationError('Please use a different email address.')


class ResetPasswordRequestForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Request Password Reset')


class UploadForm(FlaskForm):
    file = FileField()


class JobForm(FlaskForm):
    """
    Form for creating and editing Job instances.
    """
    class Meta:
        csrf = True

    def __init__(self, line_type=None, *args, **kwargs):
        super(JobForm, self).__init__(*args, **kwargs)

        # Query active lines of the specified type
        query = Line.query
        if line_type:
            query = query.filter_by(type_id=line_type)
            
        # Populate the choices and append tag disabled if needed
        self.line_id.choices = [
            (line.id, f"{line.description} (disabled)" if not line.is_enabled else line.description) for line in query.all()
        ]

    def validate_datetime_format(self, field):
        if field.raw_data is None:
            return
        
        value = field.raw_data[0]
        
        formats = [
            '%d/%m/%Y %H:%M:%S',
            '%d/%m/%Y %H:%M',
            '%d/%m/%Y',
            '%d-%m-%Y %H:%M:%S',
            '%d-%m-%Y %H:%M',
            '%d-%m-%Y',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%d %H:%M:%S'
        ]
        
        # Try parsing with each format
        for fmt in formats:
            try:
                datetime.strptime(value, fmt)
                return  # Valid format found
            except ValueError:
                continue
        
        # If we get here, no format matched
        valid_formats = [
            'DD/MM/YYYY HH:mm:ss',
            'DD/MM/YYYY HH:mm',
            'DD/MM/YYYY'
        ]
        raise ValidationError(f'Accepted formats are: <br> - {"<br> - ".join(valid_formats)}')

    def validate_duration(self, field):
        # raw_data is not null
        if field.raw_data:
            # raw_dat validation by regexp
            pattern = r'^(?:\d+\s+([a-zA-Z]+\s+)?)?\d+:\d+(?::\d+)?$'
            if not re.match(pattern, field.raw_data[0].strip()):
                raise ValidationError("Invalid format!<br>Use hh:mm or hh:mm:ss<br><i>(Can be preceded by days if needed)</i>")

    # Basic info
    id = IntegerField(
        'Id',
        validators=[InputRequired()],
        render_kw={"readonly": True}
    )
    wo = IntegerField(
        'Work Order Number',
        validators=[InputRequired()]
    )
    batch = StringField(
        'Batch Number',
        validators=[InputRequired()]
    )

    # Foreign keys
    line_id = SelectField(
        'Line Id',
        coerce=int
    )
    status_id = IntegerField(
        'Status Id',
        validators=[NumberRange(min=1)]
    )

    # Scheduling
    planned_date = DateTimeField(
        'Planned Date',
        format=[
            '%d/%m/%Y %H:%M:%S',
            '%d/%m/%Y %H:%M',
            '%d/%m/%Y',
            '%d-%m-%Y %H:%M:%S',
            '%d-%m-%Y %H:%M',
            '%d-%m-%Y',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%d %H:%M:%S'
        ],
        validators=[
            InputRequired(),
            validate_datetime_format
        ],
        render_kw={
            "class": "datepicker",
            "placeholder": "e.g. DD/MM/YYYY HH:mm:ss"
        }
    )
    duration = DurationField(
        'Duration',
        validators=[
            InputRequired()
        ],
        render_kw={
            "placeholder": "e.g. 1 day 05:30:02 or 05:30"
        }
    )
    prio_date = DateTimeField(
        'Prio Date',
        format=[
            '%d/%m/%Y %H:%M:%S',
            '%d/%m/%Y %H:%M',
            '%d/%m/%Y',
            '%d-%m-%Y %H:%M:%S',
            '%d-%m-%Y %H:%M',
            '%d-%m-%Y',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%d %H:%M:%S'
        ],
        validators=[
            Optional(),
            validate_datetime_format
        ],
        render_kw={
            "class": "datepicker",
            "placeholder": "e.g. DD/MM/YYYY HH:mm:ss"
        }
    )

    # Quantity info
    planned_qty = IntegerField(
        'Planned Qty',
        validators=[
            InputRequired(),
            NumberRange(min=1)
        ]
    )
    exact_qty = BooleanField('Exact Qty')
    remaining_qty = BooleanField('Remaining Qty')

    # Product info
    is_pq = BooleanField('Is PQ')
    product_type_id = IntegerField(
        'Product Type Id',
        validators=[Optional()]
    )
    item = StringField('Item')
    description = StringField('Description')
    setup = StringField('Setup')

    submit = SubmitField('Save')
    