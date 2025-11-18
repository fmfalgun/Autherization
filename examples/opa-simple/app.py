#!/usr/bin/env python3
"""
Simple OPA Authorization Client

This script demonstrates how to query OPA for authorization decisions.
"""

import requests
import json
from typing import Dict, Any
from dataclasses import dataclass


@dataclass
class AuthRequest:
    """Authorization request structure"""
    user: str
    action: str
    resource: str


class OPAClient:
    """Client for querying OPA server"""

    def __init__(self, opa_url: str = "http://localhost:8181"):
        self.opa_url = opa_url
        self.policy_path = "authz/allow"

    def check_permission(self, user: str, action: str, resource: str) -> bool:
        """
        Check if a user can perform an action on a resource

        Args:
            user: Username
            action: Action to perform (read, write, delete)
            resource: Resource identifier

        Returns:
            True if allowed, False otherwise
        """
        url = f"{self.opa_url}/v1/data/{self.policy_path}"

        payload = {
            "input": {
                "user": user,
                "action": action,
                "resource": resource
            }
        }

        try:
            response = requests.post(url, json=payload, timeout=5)
            response.raise_for_status()
            result = response.json()
            return result.get("result", False)
        except requests.exceptions.RequestException as e:
            print(f"Error querying OPA: {e}")
            return False

    def get_allowed_actions(self, user: str, resource: str) -> list:
        """
        Get all allowed actions for a user on a resource

        Args:
            user: Username
            resource: Resource identifier

        Returns:
            List of allowed actions
        """
        url = f"{self.opa_url}/v1/data/authz/allowed_actions"

        payload = {
            "input": {
                "user": user,
                "resource": resource
            }
        }

        try:
            response = requests.post(url, json=payload, timeout=5)
            response.raise_for_status()
            result = response.json()
            return result.get("result", [])
        except requests.exceptions.RequestException as e:
            print(f"Error querying OPA: {e}")
            return []

    def health_check(self) -> bool:
        """Check if OPA server is healthy"""
        try:
            response = requests.get(f"{self.opa_url}/health", timeout=5)
            return response.status_code == 200
        except requests.exceptions.RequestException:
            return False


def print_result(description: str, user: str, action: str, resource: str, allowed: bool):
    """Pretty print authorization result"""
    status = "✅ ALLOWED" if allowed else "❌ DENIED"
    print(f"\n{description}")
    print(f"  User: {user}")
    print(f"  Action: {action}")
    print(f"  Resource: {resource}")
    print(f"  Result: {status}")


def main():
    """Run authorization examples"""
    print("=" * 60)
    print("OPA Authorization Examples")
    print("=" * 60)

    # Initialize OPA client
    client = OPAClient()

    # Check if OPA is running
    if not client.health_check():
        print("\n❌ Error: OPA server is not running!")
        print("Please start OPA with: docker-compose up -d")
        return

    print("\n✅ OPA server is healthy\n")

    # Example 1: Admin can do anything
    print("\n" + "=" * 60)
    print("Example 1: Admin Permissions")
    print("=" * 60)

    allowed = client.check_permission("alice", "read", "document123")
    print_result("Alice (admin) reading any document", "alice", "read", "document123", allowed)

    allowed = client.check_permission("alice", "write", "document123")
    print_result("Alice (admin) writing any document", "alice", "write", "document123", allowed)

    allowed = client.check_permission("alice", "delete", "document456")
    print_result("Alice (admin) deleting any document", "alice", "delete", "document456", allowed)

    # Example 2: Editor permissions
    print("\n" + "=" * 60)
    print("Example 2: Editor Permissions")
    print("=" * 60)

    allowed = client.check_permission("bob", "read", "document123")
    print_result("Bob (editor) reading his own document", "bob", "read", "document123", allowed)

    allowed = client.check_permission("bob", "write", "document123")
    print_result("Bob (editor) writing his own document", "bob", "write", "document123", allowed)

    allowed = client.check_permission("bob", "write", "document456")
    print_result("Bob (editor) writing Diana's document", "bob", "write", "document456", allowed)

    allowed = client.check_permission("bob", "delete", "document123")
    print_result("Bob (editor) deleting his own document", "bob", "delete", "document123", allowed)

    # Example 3: Viewer permissions
    print("\n" + "=" * 60)
    print("Example 3: Viewer Permissions")
    print("=" * 60)

    allowed = client.check_permission("charlie", "read", "document123")
    print_result("Charlie (viewer) reading any document", "charlie", "read", "document123", allowed)

    allowed = client.check_permission("charlie", "write", "document123")
    print_result("Charlie (viewer) writing any document", "charlie", "write", "document123", allowed)

    allowed = client.check_permission("charlie", "delete", "document123")
    print_result("Charlie (viewer) deleting any document", "charlie", "delete", "document123", allowed)

    # Example 4: Get all allowed actions
    print("\n" + "=" * 60)
    print("Example 4: Query Allowed Actions")
    print("=" * 60)

    actions = client.get_allowed_actions("bob", "document123")
    print(f"\nBob's allowed actions on document123: {actions}")

    actions = client.get_allowed_actions("charlie", "document123")
    print(f"Charlie's allowed actions on document123: {actions}")

    # Example 5: Edge cases
    print("\n" + "=" * 60)
    print("Example 5: Edge Cases")
    print("=" * 60)

    allowed = client.check_permission("unknown_user", "read", "document123")
    print_result("Unknown user trying to read", "unknown_user", "read", "document123", allowed)

    allowed = client.check_permission("charlie", "execute", "document123")
    print_result("Valid user with invalid action", "charlie", "execute", "document123", allowed)

    print("\n" + "=" * 60)
    print("Examples Complete!")
    print("=" * 60)
    print("\nTry modifying the policy.rego file and reload it to see changes.")
    print("Reload command: make load-policy\n")


if __name__ == "__main__":
    main()
