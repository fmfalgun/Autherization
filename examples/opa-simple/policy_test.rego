package authz

# Test data
test_users := {
    "alice": {"roles": ["admin"]},
    "bob": {"roles": ["editor"]},
    "charlie": {"roles": ["viewer"]}
}

test_resources := {
    "doc1": {"owner": "bob"},
    "doc2": {"owner": "alice"}
}

# Test: Admin can do anything
test_admin_can_read {
    allow with input as {"user": "alice", "action": "read", "resource": "doc1"}
        with data.users as test_users
        with data.resources as test_resources
}

test_admin_can_write {
    allow with input as {"user": "alice", "action": "write", "resource": "doc1"}
        with data.users as test_users
        with data.resources as test_resources
}

test_admin_can_delete {
    allow with input as {"user": "alice", "action": "delete", "resource": "doc1"}
        with data.users as test_users
        with data.resources as test_resources
}

# Test: Editor can read any resource
test_editor_can_read_any {
    allow with input as {"user": "bob", "action": "read", "resource": "doc2"}
        with data.users as test_users
        with data.resources as test_resources
}

# Test: Editor can write own resource
test_editor_can_write_own {
    allow with input as {"user": "bob", "action": "write", "resource": "doc1"}
        with data.users as test_users
        with data.resources as test_resources
}

# Test: Editor cannot write others' resources
test_editor_cannot_write_others {
    not allow with input as {"user": "bob", "action": "write", "resource": "doc2"}
        with data.users as test_users
        with data.resources as test_resources
}

# Test: Editor can delete own resource
test_editor_can_delete_own {
    allow with input as {"user": "bob", "action": "delete", "resource": "doc1"}
        with data.users as test_users
        with data.resources as test_resources
}

# Test: Editor cannot delete others' resources
test_editor_cannot_delete_others {
    not allow with input as {"user": "bob", "action": "delete", "resource": "doc2"}
        with data.users as test_users
        with data.resources as test_resources
}

# Test: Viewer can read
test_viewer_can_read {
    allow with input as {"user": "charlie", "action": "read", "resource": "doc1"}
        with data.users as test_users
        with data.resources as test_resources
}

# Test: Viewer cannot write
test_viewer_cannot_write {
    not allow with input as {"user": "charlie", "action": "write", "resource": "doc1"}
        with data.users as test_users
        with data.resources as test_resources
}

# Test: Viewer cannot delete
test_viewer_cannot_delete {
    not allow with input as {"user": "charlie", "action": "delete", "resource": "doc1"}
        with data.users as test_users
        with data.resources as test_resources
}

# Test: Unknown user denied
test_unknown_user_denied {
    not allow with input as {"user": "unknown", "action": "read", "resource": "doc1"}
        with data.users as test_users
        with data.resources as test_resources
}

# Test: Default deny
test_default_deny {
    not allow with input as {"user": "charlie", "action": "execute", "resource": "doc1"}
        with data.users as test_users
        with data.resources as test_resources
}
