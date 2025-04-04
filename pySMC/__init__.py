import os
import sys
import logging

from flask import Flask, session
from flask_wtf import CSRFProtect
from sqlalchemy import func

from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, current_user
from logging.handlers import SMTPHandler, RotatingFileHandler
from flask_mail import Mail
from flask_admin import Admin, AdminIndexView
from flask_admin.contrib.sqla import ModelView
from flask import redirect, url_for, request
from flask_principal import Principal
from pySMC.custom_fields import DurationField
from sqlalchemy.orm import joinedload, configure_mappers


class BaseAdminIndexView(AdminIndexView):
    def is_accessible(self):
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login', next=request.url))


class BaseView(ModelView):
    # form_base_class = SecureForm

    def is_accessible(self):
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login', next=request.url))


class TempView(BaseView):
    page_size = 25

    can_create = True
    can_edit = True
    can_delete = True

    create_modal = True
    edit_modal = True

    can_export = True

    column_formatters = {
        'created_by_id': lambda v, c, m, p: User.query.get(m.created_by_id).username if m.created_by_id else None,
        'updated_by_id': lambda v, c, m, p: User.query.get(m.updated_by_id).username if m.updated_by_id else None,
        'deleted_by_id': lambda v, c, m, p: User.query.get(m.updated_by_id).username if m.updated_by_id else None,
    }

    column_labels = {
        'created_by_id': 'Created By',
        'created_at': 'Created At (UTC)',
        'updated_by_id': 'Updated By',
        'updated_at': 'Updated At (UTC)',
        'deleted_by_id': 'Deleted By',
        'deleted_at': 'Deleted At (UTC)',
    }


class AllColumnView(BaseView):
    def scaffold_list_columns(self):
        return [c.key for c in self.model.__table__.columns]


def init_webhooks(_):
    # Update inbound traffic via APIs to use the public-facing ngrok URL
    pass


def create_app():
    myapp = Flask(__name__)

    # Initialize our ngrok settings into Flask
    myapp.config.from_mapping(
        BASE_URL="http://localhost:5000",
        USE_NGROK=os.environ.get("USE_NGROK", "False") == "True" and os.environ.get("WERKZEUG_RUN_MAIN") != "true"
    )

    if myapp.config["USE_NGROK"] and os.environ.get("NGROK_AUTHTOKEN"):
        # pyngrok will only be installed, and should only ever be initialized, in a dev environment
        from pyngrok import ngrok

        # Get the dev server port (defaults to 5000 for Flask, can be overridden with `--port`
        # when starting the server
        port = sys.argv[sys.argv.index("--port") + 1] if "--port" in sys.argv else "5000"

        # Open a ngrok tunnel to the dev server
        public_url = ngrok.connect(port).public_url
        print(f" * ngrok tunnel \"{public_url}\" -> \"http://127.0.0.1:{port}\"")

        # Update any base URLs or webhooks to use the public ngrok URL
        myapp.config["BASE_URL"] = public_url
        init_webhooks(public_url)

    return myapp


app = create_app()

app.config.from_object(Config)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login = LoginManager(app)
login.login_view = 'login'
mail = Mail(app)
admin = Admin(app, name='pySMC', template_mode='bootstrap4', index_view=BaseAdminIndexView())
principal = Principal(app)
csrf = CSRFProtect(app)

if not app.debug:
    if app.config['MAIL_SERVER']:
        auth = None
        if app.config['MAIL_USERNAME'] or app.config['MAIL_PASSWORD']:
            auth = (app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
        secure = None
        if app.config['MAIL_USE_TLS']:
            secure = ()
        mail_handler = SMTPHandler(
            mailhost=(app.config['MAIL_SERVER'], app.config['MAIL_PORT']),
            fromaddr='no-reply@' + app.config['MAIL_SERVER'],
            toaddrs=app.config['ADMINS'], subject='pySMC Failure',
            credentials=auth, secure=secure)
        mail_handler.setLevel(logging.ERROR)
        app.logger.addHandler(mail_handler)

    if not os.path.exists('logs'):
        os.mkdir('logs')
    file_handler = RotatingFileHandler('logs/pySMC.log', maxBytes=10240,
                                       backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)

    app.logger.setLevel(logging.INFO)
    app.logger.info('pySMC startup')

from pySMC import routes, models, errors
from pySMC.models import User, Role, UserRole, Job, Line, LineType, Status, Transition, TransitionRole


class MyModelView(TempView):
    pass


class UserView(TempView):
    column_list = ['id', 'username', 'last_name', 'first_name', 'email', 'roles', 'is_enabled', 'last_seen', 'created_at', 'created_by_id', 'updated_at', 'updated_by_id']
    form_columns = ['username', 'last_name', 'first_name', 'email', 'is_enabled']
    column_searchable_list = ['id', 'username', 'last_name', 'first_name']
    
    column_formatters = {
        'roles': lambda v, c, m, p: ', '.join([a.description for a in m.roles]),
        'created_by_id': lambda v, c, m, p: User.query.get(m.created_by_id).username if m.created_by_id else None,
        'updated_by_id': lambda v, c, m, p: User.query.get(m.updated_by_id).username if m.updated_by_id else None,
    }

    def scaffold_list_columns(self):
        columns = super(UserView, self).scaffold_list_columns()
        return ['id'] + columns + ['created_at', 'created_by_id', 'updated_at', 'updated_by_id']


class RoleView(TempView):
    column_searchable_list = ['id', 'name', 'description']
    form_excluded_columns = ['users', 'role_users', 'role_transitions', 'created_at', 'updated_at']

    def scaffold_list_columns(self):
        columns = super(RoleView, self).scaffold_list_columns()
        columns.remove('created_at')
        columns.remove('updated_at')
        return ['id'] + columns + ['created_at', 'created_by_id', 'updated_at', 'updated_by_id']


class UserRoleView(TempView):
    column_searchable_list = ['user.username', 'role.name']
    form_columns = ['user', 'role', 'is_enabled']
      
    def scaffold_list_columns(self):
        columns = super(UserRoleView, self).scaffold_list_columns()
        columns.remove('created_at')
        columns.remove('updated_at')
        return ['id'] + columns + ['created_at', 'created_by_id', 'updated_at', 'updated_by_id']  

    def get_query(self):
        return self.session.query(self.model).options(joinedload(UserRole.user), joinedload(UserRole.role))

    def get_count_query(self):
        return self.session.query(func.count('*')).select_from(self.model).join(UserRole.user).join(UserRole.role)


class JobView(TempView):
    column_searchable_list = ['wo', 'batch']
    form_excluded_columns = ['created_at', 'updated_at']
 
    form_overrides = {
        'duration': DurationField
    }

    def scaffold_list_columns(self):
        columns = super(JobView, self).scaffold_list_columns()
        columns.remove('created_at')
        columns.remove('updated_at')
        return ['id'] + columns + ['created_at', 'created_by_id', 'updated_at', 'updated_by_id']

    column_formatters = {
        'status_id'
        'line': lambda v, c, m, p: Line.query.get(m.line_id).description if m.line_id else None,
        'created_by_id': lambda v, c, m, p: User.query.get(m.created_by_id).username if m.created_by_id else None,
        'updated_by_id': lambda v, c, m, p: User.query.get(m.updated_by_id).username if m.updated_by_id else None,
    }


class LineView(TempView):
    column_searchable_list = ['description']
    form_excluded_columns = ['jobs', 'created_at', 'updated_at']
       
    def scaffold_list_columns(self):
        columns = super(LineView, self).scaffold_list_columns()
        columns.remove('created_at')
        columns.remove('updated_at')
        return ['id'] + columns + ['created_at', 'created_by_id', 'updated_at', 'updated_by_id']


class LineTypeView(TempView):
    column_searchable_list = ['description']
    form_excluded_columns = ['lines', 'created_at', 'updated_at']
       
    def scaffold_list_columns(self):
        columns = super(LineTypeView, self).scaffold_list_columns()
        columns.remove('created_at')
        columns.remove('updated_at')
        return ['id'] + columns + ['created_at', 'created_by_id', 'updated_at', 'updated_by_id']


class StatusView(TempView):
    column_searchable_list = ['status', 'state']
    form_excluded_columns = ['jobs', 'previous_statuses', 'following_statuses', 'prev_transitions', 'foll_transitions', 'created_at', 'updated_at']

    column_formatters = {
        'previous_statuses': lambda v, c, m, p: ', '.join([a.state for a in m.previous_statuses]),
        'following_statuses': lambda v, c, m, p: ', '.join([a.state for a in m.following_statuses]),
        'created_by_id': lambda v, c, m, p: User.query.get(m.created_by_id).username if m.created_by_id else None,
        'updated_by_id': lambda v, c, m, p: User.query.get(m.updated_by_id).username if m.updated_by_id else None,
    }

    def scaffold_list_columns(self):
        columns = super(StatusView, self).scaffold_list_columns()
        columns.remove('created_at')
        columns.remove('updated_at')
        return ['id'] + columns + ['previous_statuses', 'following_statuses', 'created_at', 'created_by_id', 'updated_at', 'updated_by_id']


class TransitionView(TempView):
    form_excluded_columns = ['transition_roles', 'created_at', 'updated_at']
       
    def scaffold_list_columns(self):
        columns = super(TransitionView, self).scaffold_list_columns()
        columns.remove('created_at')
        columns.remove('updated_at')
        return ['id'] + columns + ['created_at', 'created_by_id', 'updated_at', 'updated_by_id']


class TransitionRoleView(TempView):
    #column_searchable_list = ['user.username', 'role.name']
    form_columns = ['transition', 'role', 'is_enabled']
      
    def scaffold_list_columns(self):
        columns = super(TransitionRoleView, self).scaffold_list_columns()
        columns.remove('created_at')
        columns.remove('updated_at')
        return ['id'] + columns + ['created_at', 'created_by_id', 'updated_at', 'updated_by_id']  

    def get_query(self):
        return self.session.query(self.model).options(joinedload(TransitionRole.transition), joinedload(TransitionRole.role))

    def get_count_query(self):
        return self.session.query(func.count('*')).select_from(self.model).join(TransitionRole.transition).join(TransitionRole.role)


with app.app_context():
    configure_mappers()
    admin.add_view(UserView(User, db.session, category="User"))
    admin.add_view(RoleView(Role, db.session, category="User"))
    admin.add_view(UserRoleView(UserRole, db.session, category="User"))
    admin.add_view(JobView(Job, db.session, category="Job"))
    admin.add_view(LineView(Line, db.session, category="Line"))
    admin.add_view(LineTypeView(LineType, db.session, category="Line"))
    admin.add_view(StatusView(Status, db.session, category="Status"))
    admin.add_view(TransitionView(Transition, db.session, category="Status"))
    admin.add_view(TransitionRoleView(TransitionRole, db.session, category="Status"))
