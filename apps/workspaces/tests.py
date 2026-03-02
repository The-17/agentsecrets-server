import uuid
from django.test import TestCase
from rest_framework.test import APIClient
from django.urls import reverse
from apps.accounts.models import User
from .models import Workspace, MembershipRole, WorkspaceType, WorkspaceAllowlist, Membership, MembershipStatus

class WorkspaceAllowlistTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(email='test@example.com', password='password123', first_name='Test', last_name='User')
        self.admin_user = User.objects.create_user(email='admin@example.com', password='password123', first_name='Admin', last_name='User')
        self.member_user = User.objects.create_user(email='member@example.com', password='password123', first_name='Member', last_name='User')
        
        # Create workspace
        self.workspace = Workspace.objects.create(name='Test Workspace', owner=self.admin_user, type=WorkspaceType.SHARED)
        
        # Add admin membership
        self.admin_membership = Membership.objects.create(
            user=self.admin_user, 
            workspace=self.workspace, 
            role=MembershipRole.ADMIN,
            status=MembershipStatus.ACTIVE,
            encrypted_workspace_key='key'
        )
        
        # Add member membership
        self.member_membership = Membership.objects.create(
            user=self.member_user, 
            workspace=self.workspace, 
            role=MembershipRole.MEMBER,
            status=MembershipStatus.ACTIVE,
            encrypted_workspace_key='key'
        )

    def test_add_domain_as_admin(self):
        self.client.force_authenticate(user=self.admin_user)
        url = reverse('workspace-allowlist', kwargs={'workspace_id': self.workspace.id})
        data = {'domain': 'example.com'}
        
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, 201)
        self.assertEqual(WorkspaceAllowlist.objects.count(), 1)

    def test_add_domain_as_member(self):
        self.client.force_authenticate(user=self.member_user)
        url = reverse('workspace-allowlist', kwargs={'workspace_id': self.workspace.id})
        data = {'domain': 'example.com'}
        
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, 403)
        self.assertEqual(WorkspaceAllowlist.objects.count(), 0)

    def test_list_domains_as_member(self):
        WorkspaceAllowlist.objects.create(workspace=self.workspace, domain='example.com', added_by=self.admin_user)
        
        self.client.force_authenticate(user=self.member_user)
        url = reverse('workspace-allowlist', kwargs={'workspace_id': self.workspace.id})
        
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['data']), 1)

    def test_remove_domain_as_admin(self):
        WorkspaceAllowlist.objects.create(workspace=self.workspace, domain='example.com', added_by=self.admin_user)
        
        self.client.force_authenticate(user=self.admin_user)
        url = reverse('workspace-allowlist-detail', kwargs={'workspace_id': self.workspace.id, 'domain': 'example.com'})
        
        response = self.client.delete(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(WorkspaceAllowlist.objects.count(), 0)

    def test_invalid_domain(self):
        self.client.force_authenticate(user=self.admin_user)
        url = reverse('workspace-allowlist', kwargs={'workspace_id': self.workspace.id})
        data = {'domain': 'invalid domain space'}
        
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, 400)
        self.assertIn('Invalid domain format.', response.data['message'])

    def test_domain_stripping(self):
        self.client.force_authenticate(user=self.admin_user)
        url = reverse('workspace-allowlist', kwargs={'workspace_id': self.workspace.id})
        data = {'domain': 'https://example.com/api/v1'}
        
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, 201)
        self.assertEqual(WorkspaceAllowlist.objects.get().domain, 'example.com')
        
    def test_promote_member(self):
        self.client.force_authenticate(user=self.admin_user)
        url = reverse('workspace-member-role', kwargs={'workspace_id': self.workspace.id, 'user_id': self.member_user.id})
        data = {'action': 'promote'}
        
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, 200)
        
        self.member_membership.refresh_from_db()
        self.assertEqual(self.member_membership.role, MembershipRole.ADMIN)
