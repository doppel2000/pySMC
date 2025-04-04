from flask import render_template, flash, redirect, url_for, request, abort, session, jsonify
from sqlalchemy import func, and_, or_
from werkzeug.exceptions import NotFound
from config import Config

from pySMC import app, db
from pySMC.custom_fields import parse_duration
from pySMC.forms import LoginForm, RegistrationForm, ResetPasswordRequestForm, ResetPasswordForm, JobForm, UploadForm
from flask_login import current_user, login_user, logout_user, login_required
from flask_principal import Identity, AnonymousIdentity, identity_loaded, RoleNeed, Permission, UserNeed, \
                            identity_changed
import sqlalchemy as sa
from pySMC.models import User, Job, Status, Line, Transition, UserRole, TransitionRole
from urllib.parse import urlsplit
from datetime import datetime, timezone
from pySMC.email import send_password_reset_email

from pySMC.search_parser import parse_search_query
from pySMC.utils import strtobool, validate_date, utc_date
from pySMC.InitDB import init_db

# Define roles
super_admin_role = RoleNeed('super_admin')
admin_role = RoleNeed('admin')
basic_planning_role = RoleNeed('basic_planning')

# Define permissions
can_add_permission = Permission(super_admin_role, admin_role)
can_edit_permission = Permission(super_admin_role, admin_role, basic_planning_role)
can_edit_in_cell_permission = Permission(super_admin_role)
can_delete_permission = Permission(super_admin_role)
can_update_planning_permission = Permission(super_admin_role, admin_role, basic_planning_role)
can_make_projection_permission = Permission(super_admin_role, admin_role)


@identity_loaded.connect_via(app)
def on_identity_loaded(_, identity):
    if not isinstance(identity, AnonymousIdentity):
        identity.user = current_user
        if hasattr(current_user, 'id'):
            identity.provides.add(UserNeed(current_user.id))
            for role in current_user.get_roles():
                identity.provides.add(RoleNeed(role.name))


@app.before_request
def before_request():
    session.permanent = True
    if current_user.is_authenticated:
        current_user.last_seen = datetime.now(timezone.utc)
        db.session.commit()


@app.route('/', methods=['GET', 'POST'])
@app.route('/index', methods=['GET', 'POST'])
@login_required
def index():
    return render_template('index.html', title='Home')


@app.route('/api/data', methods=['GET', 'POST'])
@login_required
def api_data():
    if request.method == 'GET':
        query = Job.query.join(Status).join(Line)

        # search filter
        search = request.args.get('search')

        if search:
            search_conditions = parse_search_query(search)
            if search_conditions is not None:
                query = query.filter(search_conditions)

        total = query.count()

        # sorting
        sort = request.args.get('sort')
        if sort:
            order = []
            for s in sort.split(','):
                direction = s[0]
                name = s[1:]
                if name not in ['id', 'wo', 'batch', 'planned_date', 'duration', 'planned_qty', 'exact_qty', 'remaining_qty', 'is_pq', 'product_type_id', 'item', 'description', 'setup', 'prio_date', 'status', 'state', 'line']:
                    print('Invalid sorting column')
                    name = 'id'

                if name == 'status':
                    col = Status.status
                elif name == 'state':
                    col = Status.state
                elif name == 'line':
                    col = Line.description
                elif name == 'duration':
                    col = func.extract('epoch', Job.duration)
                else:
                    col = getattr(Job, name)

                if direction == '-':
                    col = col.desc()
                order.append(col)
            if order:
                query = query.order_by(*order)

        # pagination
        start = request.args.get('start', type=int, default=-1)
        length = request.args.get('length', type=int, default=-1)
        if start != -1 and length != -1:
            query = query.offset(start).limit(length)

        # response
        return {
            'data': [job.to_dict() for job in query],
            'total': total,
        }
    elif request.method == 'POST':
        data = request.get_json()
        if 'id' not in data:
            abort(400)
        job = Job.query.get(data['id'])
        for field in ['line_id', 'wo', 'batch', 'status_id', 'planned_date', 'duration', 'planned_qty', 'exact_qty', 'remaining_qty', 'is_pq', 'product_type_id', 'item', 'description', 'setup', 'prio_date']:
            if field in data:
                if field in ['planned_date', 'prio_date']:
                    obj = validate_date(data[field])
                    if obj:
                        obj = utc_date(obj)
                elif field in ['exact_qty', 'remaining_qty', 'is_pq']:
                    obj = strtobool(data[field])
                elif field == 'duration':
                    obj = parse_duration(data[field])
                else:
                    obj = data[field]
                if obj is not None:
                    setattr(job, field, obj)
        db.session.commit()
        return '', 204


@app.route('/planning', methods=['GET'])
@login_required
def planning():
    """
    Renders the planning page with necessary permissions and form.
    """
    
    form = JobForm(1)
    #form.line_id.choices = [(line.id, line.description) for line in Line.query.filter_by(type_id=1, is_enabled=True).all()]
    
    context = {
        'title': 'Planning',
        'form': form,
        'can_add': can_add_permission.can(),
        'can_edit': can_edit_permission.can(),
        'can_edit_in_cell': can_edit_permission.can(),
        'can_delete': can_delete_permission.can(),
        'can_update_planning': can_update_planning_permission.can(),        
        'can_make_projection': can_make_projection_permission.can(),        
        'allowed_status': current_user.get_allowed_status_id_with_direction()
    }
    return render_template('planning.html', **context)


@app.route('/planning/upload', methods=['POST'])
@login_required
@can_update_planning_permission.require(http_exception=403)
def upload():
    form = UploadForm()
    
    print("UPDATE")
    
    if form.validate_on_submit():
        filename = secure_filename(form.file.data.filename)
        form.file.data.save(Config['UPLOAD_FOLDER'] + "/" + filename)
        return jsonify({'status': 'success', 'message': f'Planning updated'}), 200


@app.route('/planning/delete', methods=['GET'])
@login_required
@can_delete_permission.require(http_exception=403)
def job_delete():
    """
    Handles the deletion of a job.
    """
    job_id = request.args.get('job_id')
    print(job_id)
    if not job_id:
        return jsonify({'status': 'warning', 'message': 'Missing job ID'}), 400

    try:
        job = Job.query.get(job_id)
        if not job:
            return jsonify({'status': 'warning', 'message': 'Job not found'}), 404

        db.session.delete(job)
        db.session.commit()
        return jsonify({'status': 'success', 'message': f'Job {job.batch} deleted'}), 200
    except Exception as e:
        app.logger.error(f"Error deleting job {job_id}: {str(e)}")
        db.session.rollback()
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500


@app.route('/planning/save', methods=['POST'])
@login_required
def job_save():
    """
    Handles job creation and updates.
    """
    form = JobForm(1)
    #form.line_id.choices = [(line.id, line.description) for line in Line.query.filter_by(type_id=1, is_enabled=True).all()]
    form.validate()
    try:
        if form.validate():
            job_id = request.form.get('id')
            job_data = _get_job_data_from_form(form)

            if job_id:  # Update existing job
                return _handle_job_update(job_id, job_data, form)
            else:  # Create new job
                return _handle_job_creation(job_data, form)
        else:
            return jsonify({'status': 'warning', 'message': 'validation failed', 'errors': form.errors}), 400
    except Exception as e:
        app.logger.error(f"Error saving job: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500


def _get_job_data_from_form(form):
    """
    Extracts job data from form fields.
    """
    return {
        'line_id': form.line_id.data,
        'wo': form.wo.data,
        'batch': form.batch.data,
        'status_id': form.status_id.data,
        'planned_date': form.planned_date.data,
        'duration': form.duration.data,
        'planned_qty': form.planned_qty.data,
        'exact_qty': form.exact_qty.data,
        'remaining_qty': form.remaining_qty.data,
        'is_pq': form.is_pq.data,
        'product_type_id': form.product_type_id.data,
        'item': form.item.data,
        'description': form.description.data,
        'setup': form.setup.data,
        'prio_date': form.prio_date.data
    }


def _handle_job_update(job_id, job_data, form):
    """
    Handles updating an existing job.
    """
    job = Job.query.get_or_404(job_id)

    if not _has_changes(job, job_data):
        return jsonify({'status': 'warning', 'message': 'No changes detected'})

    for key, value in job_data.items():
        if key in ['planned_date', 'prio_date']:
            value = utc_date(value)
        setattr(job, key, value)

    db.session.commit()
    return jsonify({'status': 'success', 'message': f'Job {form.batch.data} updated'})


def _handle_job_creation(job_data, form):
    """
    Handles creating a new job.
    """
    job = Job(**job_data)
    db.session.add(job)
    db.session.commit()
    return jsonify({'status': 'success', 'message': f'Job {form.batch.data} added'})


def _has_changes(job, new_data):
    """
    Checks if there are any changes between current job data and new data.
    """
    return any(getattr(job, key) != value for key, value in new_data.items())


@app.route('/planning/job_data', methods=['GET'])
@login_required
@can_edit_permission.require(http_exception=403)
def job_data():
    """
    Retrieves job data for editing.
    """
    job_id = request.args.get('job_id')
    if not job_id:
        return jsonify({'error': 'Missing job_id'}), 404

    try:
        job = Job.query.get(job_id)
        if not job:
            raise NotFound('Job not found')
        return jsonify(job.to_dict()), 200
    except NotFound as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        app.logger.error(f"Error fetching job {job_id}: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user_to_login = db.session.scalar(
            sa.select(User).where(User.username == form.username.data.upper()))
        if user_to_login is None or not user_to_login.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user_to_login, remember=form.remember_me.data)
        identity_changed.send(app, identity=Identity(user_to_login.id))
        next_page = request.args.get('next')
        if not next_page or urlsplit(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', title='Sign In', form=form)


@app.route('/logout')
def logout():
    logout_user()
    for key in ('identity.name', 'identity.auth_type', 'csrf_token'):
        session.pop(key, None)
    identity_changed.send(app, identity=AnonymousIdentity())
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        new_user = User(username=form.username.data.upper(), email=form.email.data, first_name=form.first_name.data, last_name=form.last_name.data)
        new_user.set_password(form.password.data)
        db.session.add(new_user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user_to_reset_password = db.session.scalar(
            sa.select(User).where(User.email == form.email.data))
        if user_to_reset_password:
            send_password_reset_email(user_to_reset_password)
        flash('Check your email for the instructions to reset your password')
        return redirect(url_for('login'))
    return render_template('reset_password_request.html', title='Reset Password', form=form)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    user_to_reset_password = User.verify_reset_password_token(token)
    if not user_to_reset_password:
        return redirect(url_for('index'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user_to_reset_password.set_password(form.password.data)
        db.session.commit()
        flash('Your password has been reset.')
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)


@app.route('/status_update', methods=['GET', 'POST'])
@login_required
def status_update():
    if request.method == 'GET':
        job_id = request.args.get('job_id')
        direction = request.args.get('direction')
        job = Job.query.get(job_id)

        if not job:
            return jsonify({"error": "Job not found"}), 404
        if not direction:
            return jsonify({"error": "Missing direction"}), 404

        user_roles = UserRole.query.filter(
            and_(
                UserRole.user_id == current_user.id,
                UserRole.is_enabled == True
            )
        ).with_entities(UserRole.role_id).all()
        user_role_ids = [r.role_id for r in user_roles]

        if direction == "forward":
            possible_transitions = Transition.query.filter(
                    and_(
                        Transition.previous_status_id == job.status_id,
                        Transition.is_enabled == True,
                        Transition.allow_forward == True
                    )
            ).all()
        elif direction == "backward":
            possible_transitions = Transition.query.filter(
                and_(
                    Transition.following_status_id == job.status_id,
                    Transition.is_enabled == True,
                    Transition.allow_backward == True
                )
            ).all()
        else:
            return jsonify({"error": "Unknown direction"}), 404

        allowed_transitions = [
            possible_transition for possible_transition in possible_transitions
            if TransitionRole.query.filter(
                and_(
                    TransitionRole.transition_id == possible_transition.id,
                    TransitionRole.role_id.in_(user_role_ids),
                    TransitionRole.is_enabled == True
                )
            ).first()
        ]

        possible_statuses = [{
                "id": status.id,
                "name": f"{status.status} - {status.state}"
            }
            for allowed_transition in allowed_transitions
                for status in [Status.query.get(
                    allowed_transition.following_status_id if direction == "forward" 
                    else allowed_transition.previous_status_id
                )]
            if status
        ]

        return jsonify({
            "job_id": job.id,
            "batch": job.batch,
            "current_status": f"{job.status.status} - {job.status.state}",
            "possible_statuses": possible_statuses
        })

    elif request.method == 'POST':
        data = request.json
        job_id = data.get('job_id')
        new_status_id = data.get('new_status_id')

        job = Job.query.get(job_id)
        if not job:
            return jsonify({"error": "Job not found"}), 404

        transition = Transition.query.filter(
            or_(
                and_(
                    Transition.previous_status_id == job.status_id,
                    Transition.following_status_id == new_status_id,
                    Transition.is_enabled == True,
                    Transition.allow_forward == True
                ),
                and_(
                    Transition.previous_status_id == new_status_id,
                    Transition.following_status_id == job.status_id,
                    Transition.is_enabled == True,
                    and_(Transition.allow_backward == True)
                )
            )
        ).first()

        if not transition:
            return jsonify({"error": "Transition not allowed"}), 403

        user_roles = UserRole.query.filter(
            and_(
                UserRole.user_id == current_user.id,
                UserRole.is_enabled == True
            )
        ).with_entities(UserRole.role_id).all()
        user_role_ids = [r.role_id for r in user_roles]

        transition_role = TransitionRole.query.filter(
            and_(
                TransitionRole.transition_id == transition.id,
                TransitionRole.role_id.in_(user_role_ids),
                TransitionRole.is_enabled == True
            )
        ).first()

        if not transition_role:
            return jsonify({"error": "User does not have permission to perform this transition"}), 403

        job.status_id = new_status_id
        db.session.commit()

        return jsonify({"message": "Status updated successfully"}), 200

    return jsonify({"error": "Invalid request method"}), 400


@app.route('/user/<username>')
@login_required
def user(username):
    selected_user = db.first_or_404(sa.select(User).where(User.username == username))
    posts = [
        {'author': selected_user, 'body': 'Test post #1'},
        {'author': selected_user, 'body': 'Test post #2'}
    ]
    return render_template('user.html', user=selected_user, posts=posts)


@app.route('/init_db', methods=['GET'])
@login_required
def initdb():
    init_db()
    flash('DB Initialized !')
    return redirect(url_for('index'))


@app.errorhandler(403)
def forbidden(error):
    return render_template('403.html'), 403
