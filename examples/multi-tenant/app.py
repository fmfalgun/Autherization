#!/usr/bin/env python3
"""
Multi-Tenant Authorization Example with Flask and OPA
"""

from flask import Flask, request, jsonify, g
from functools import wraps
import jwt
import requests
import hashlib
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = 'demo-secret-change-in-production'
OPA_URL = 'http://localhost:8181/v1/data/multitenant/authz/allow'

# In-memory data stores (use database in production)
users = {
    'alice': {
        'id': 1,
        'username': 'alice',
        'password': hashlib.sha256('alice123'.encode()).hexdigest(),
        'tenant': 'acme',
        'role': 'admin',
        'name': 'Alice Admin'
    },
    'bob': {
        'id': 2,
        'username': 'bob',
        'password': hashlib.sha256('bob123'.encode()).hexdigest(),
        'tenant': 'acme',
        'role': 'user',
        'name': 'Bob User'
    },
    'charlie': {
        'id': 3,
        'username': 'charlie',
        'password': hashlib.sha256('charlie123'.encode()).hexdigest(),
        'tenant': 'globex',
        'role': 'admin',
        'name': 'Charlie Admin'
    },
    'diana': {
        'id': 4,
        'username': 'diana',
        'password': hashlib.sha256('diana123'.encode()).hexdigest(),
        'tenant': 'globex',
        'role': 'user',
        'name': 'Diana User'
    },
    'root': {
        'id': 0,
        'username': 'root',
        'password': hashlib.sha256('root123'.encode()).hexdigest(),
        'tenant': 'system',
        'role': 'superadmin',
        'name': 'Root Superadmin'
    }
}

tenants = {
    'acme': {
        'id': 'acme',
        'name': 'Acme Corporation',
        'parent': None,
        'active': True
    },
    'globex': {
        'id': 'globex',
        'name': 'Globex Inc',
        'parent': None,
        'active': True
    },
    'system': {
        'id': 'system',
        'name': 'System',
        'parent': None,
        'active': True
    }
}

resources = [
    {'id': 1, 'tenant': 'acme', 'name': 'Acme Q1 Report', 'type': 'document'},
    {'id': 2, 'tenant': 'acme', 'name': 'Acme Strategy', 'type': 'document'},
    {'id': 3, 'tenant': 'globex', 'name': 'Globex Financials', 'type': 'spreadsheet'},
    {'id': 4, 'tenant': 'globex', 'name': 'Globex Roadmap', 'type': 'document'},
]

next_resource_id = 5

# Authentication decorator
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')

        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'No token provided'}), 401

        token = auth_header.split(' ')[1]

        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            g.user = users.get(payload['username'])

            if not g.user:
                return jsonify({'error': 'User not found'}), 401

        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401

        return f(*args, **kwargs)

    return decorated

# Authorization with OPA
def check_opa_permission(action, resource=None):
    """Check permission with OPA"""
    input_data = {
        'user': {
            'id': g.user['id'],
            'username': g.user['username'],
            'tenant': g.user['tenant'],
            'role': g.user['role']
        },
        'action': action,
        'resource': resource or {'tenant': g.user['tenant']}
    }

    try:
        response = requests.post(
            OPA_URL,
            json={'input': input_data},
            timeout=2
        )

        if response.status_code == 200:
            result = response.json()
            return result.get('result', False)
        else:
            print(f"OPA error: {response.status_code}")
            return False

    except requests.exceptions.RequestException as e:
        print(f"OPA connection error: {e}")
        # Fail closed - deny if OPA unavailable
        return False

# Routes

@app.route('/health')
def health():
    return jsonify({'status': 'healthy', 'service': 'multi-tenant-api'})

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    user = users.get(username)

    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401

    password_hash = hashlib.sha256(password.encode()).hexdigest()

    if user['password'] != password_hash:
        return jsonify({'error': 'Invalid credentials'}), 401

    # Generate JWT
    token = jwt.encode({
        'username': user['username'],
        'tenant': user['tenant'],
        'role': user['role'],
        'exp': datetime.utcnow() + timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm='HS256')

    return jsonify({
        'token': token,
        'user': {
            'username': user['username'],
            'name': user['name'],
            'tenant': user['tenant'],
            'role': user['role']
        }
    })

@app.route('/api/resources', methods=['GET'])
@require_auth
def list_resources():
    # Filter resources by user's tenant (unless superadmin)
    if g.user['role'] == 'superadmin':
        accessible = resources
    else:
        accessible = [r for r in resources if r['tenant'] == g.user['tenant']]

    return jsonify({'resources': accessible})

@app.route('/api/resources', methods=['POST'])
@require_auth
def create_resource():
    global next_resource_id

    if not check_opa_permission('create'):
        return jsonify({'error': 'Forbidden'}), 403

    data = request.json
    new_resource = {
        'id': next_resource_id,
        'tenant': g.user['tenant'],  # Always use authenticated user's tenant
        'name': data.get('name'),
        'type': data.get('type', 'document')
    }

    resources.append(new_resource)
    next_resource_id += 1

    return jsonify({'resource': new_resource}), 201

@app.route('/api/resources/<int:resource_id>', methods=['GET'])
@require_auth
def get_resource(resource_id):
    resource = next((r for r in resources if r['id'] == resource_id), None)

    if not resource:
        return jsonify({'error': 'Resource not found'}), 404

    # Check OPA permission
    if not check_opa_permission('read', resource):
        return jsonify({'error': 'Forbidden'}), 403

    return jsonify({'resource': resource})

@app.route('/api/resources/<int:resource_id>', methods=['PUT'])
@require_auth
def update_resource(resource_id):
    resource = next((r for r in resources if r['id'] == resource_id), None)

    if not resource:
        return jsonify({'error': 'Resource not found'}), 404

    # Check OPA permission
    if not check_opa_permission('update', resource):
        return jsonify({'error': 'Forbidden'}), 403

    data = request.json
    if 'name' in data:
        resource['name'] = data['name']
    if 'type' in data:
        resource['type'] = data['type']

    return jsonify({'resource': resource})

@app.route('/api/resources/<int:resource_id>', methods=['DELETE'])
@require_auth
def delete_resource(resource_id):
    global resources

    resource = next((r for r in resources if r['id'] == resource_id), None)

    if not resource:
        return jsonify({'error': 'Resource not found'}), 404

    # Check OPA permission
    if not check_opa_permission('delete', resource):
        return jsonify({'error': 'Forbidden'}), 403

    resources = [r for r in resources if r['id'] != resource_id]

    return jsonify({'message': 'Resource deleted'})

@app.route('/api/tenants', methods=['GET'])
@require_auth
def list_tenants():
    # Only superadmins can list all tenants
    if g.user['role'] != 'superadmin':
        return jsonify({'error': 'Forbidden'}), 403

    return jsonify({'tenants': list(tenants.values())})

@app.route('/api/tenants/<tenant_id>', methods=['GET'])
@require_auth
def get_tenant(tenant_id):
    tenant = tenants.get(tenant_id)

    if not tenant:
        return jsonify({'error': 'Tenant not found'}), 404

    # Check if user can access this tenant
    if g.user['role'] != 'superadmin' and g.user['tenant'] != tenant_id:
        return jsonify({'error': 'Forbidden'}), 403

    return jsonify({'tenant': tenant})

if __name__ == '__main__':
    print('=' * 60)
    print('Multi-Tenant Authorization API')
    print('=' * 60)
    print('\nTest credentials:')
    print('  Acme Admin:   alice / alice123')
    print('  Acme User:    bob / bob123')
    print('  Globex Admin: charlie / charlie123')
    print('  Globex User:  diana / diana123')
    print('  Superadmin:   root / root123')
    print('\nStarting server on http://localhost:5000')
    print('Make sure OPA is running on http://localhost:8181\n')

    app.run(host='0.0.0.0', port=5000, debug=True)
