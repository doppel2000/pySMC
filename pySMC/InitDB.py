from pySMC.models import Role, UserRole, Line, LineType, Status, Transition, TransitionRole
from pySMC import db


def init_db():
    roles_data = [
        {'name': 'super_admin', 'description': 'God Mode'},
        {'name': 'admin', 'description': 'Administrator'},
        {'name': 'user', 'description': 'Basic User'},
        {'name': 'basic_planning', 'description': 'Job Planning'},
        {'name': 'basic_printing', 'description': 'Job Printing'},
    ]

    user_roles_data = [
        {'user_id': 1, 'role_id': 1},
        {'user_id': 1, 'role_id': 2},
        {'user_id': 1, 'role_id': 3},
        {'user_id': 1, 'role_id': 5},
    ]

    line_types_data = [
        {'description': 'PACKING'},
        {'description': 'VISUAL INSPECTION'},
        {'description': 'BULKPACK'},
    ]

    lines_data = [
        {'description': 'L1', 'type_id': 1},
        {'description': 'L2', 'type_id': 1},
        {'description': 'L3', 'type_id': 1},
        {'description': '503', 'type_id': 2},
    ]

    statuses_data = [
        {'status': 10, 'state': 'Job planned', 'is_enabled': True},
        {'status': 20, 'state': 'Job printed', 'is_enabled': True},
        {'status': 30, 'state': '1st page released', 'is_enabled': True},
        {'status': 40, 'state': 'Job released', 'is_enabled': True},
    ]

    transitions_data = [
        {'previous_status_id': 1, 'following_status_id': 2, 'allow_forward': True, 'allow_backward': True, 'is_enabled': True},
        {'previous_status_id': 2, 'following_status_id': 3, 'allow_forward': True, 'allow_backward': True, 'is_enabled': True},
        {'previous_status_id': 3, 'following_status_id': 4, 'allow_forward': True, 'allow_backward': True, 'is_enabled': True},
        {'previous_status_id': 1, 'following_status_id': 3, 'allow_forward': False, 'allow_backward': True, 'is_enabled': True},
        {'previous_status_id': 1, 'following_status_id': 4, 'allow_forward': False, 'allow_backward': True, 'is_enabled': True},
    ]

    transition_roles_data = [
        {'transition_id': 1, 'role_id': 5, 'is_enabled': True},
    ]

    try:
        # Create Role instances
        new_roles = [Role(name=role['name'],
                          description=role['description']) for role in roles_data]
        new_user_roles = [UserRole(user_id=user_roles['user_id'],
                                   role_id=user_roles['role_id']) for user_roles in user_roles_data]
        new_line_types = [LineType(description=line_type['description']) for line_type in line_types_data]
        new_lines = [Line(description=line['description'],
                          type_id=line['type_id']) for line in lines_data]
        new_statuses = [Status(status=status['status'],
                               state=status['state'],
                               is_enabled=status['is_enabled']) for status in statuses_data]
        new_transitions = [Transition(previous_status_id=transition['previous_status_id'],
                                      following_status_id=transition['following_status_id'],
                                      allow_forward=transition['allow_forward'],
                                      allow_backward=transition['allow_backward'],
                                      is_enabled=transition['is_enabled']) for transition in transitions_data]
        new_transition_roles = [TransitionRole(transition_id=transition_role['transition_id'],
                                               role_id=transition_role['role_id'],
                                               is_enabled=transition_role['is_enabled']) for transition_role in transition_roles_data]

        # Add all new roles to the session
        db.session.add_all(new_roles)
        db.session.add_all(new_user_roles)
        db.session.add_all(new_line_types)
        db.session.add_all(new_lines)
        db.session.add_all(new_statuses)
        db.session.add_all(new_transitions)
        db.session.add_all(new_transition_roles)

        # Commit the transaction
        db.session.commit()
    except Exception as e:
        # Rollback in case of error
        db.session.rollback()
        print(f"An error occurred: {e}")
    finally:
        # Close the session
        db.session.close()
