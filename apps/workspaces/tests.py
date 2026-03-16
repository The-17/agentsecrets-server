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
        data = {'domains': ['example.com', 'example2.com']}
        
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, 201)
        self.assertEqual(WorkspaceAllowlist.objects.count(), 2)

    def test_add_domain_as_member(self):
        self.client.force_authenticate(user=self.member_user)
        url = reverse('workspace-allowlist', kwargs={'workspace_id': self.workspace.id})
        data = {'domains': ['example.com']}
        
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
        data = {'domains': ['invalid domain space']}
        
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, 400)
        self.assertIn('Invalid domain format', str(response.content))

    def test_domain_stripping(self):
        self.client.force_authenticate(user=self.admin_user)
        url = reverse('workspace-allowlist', kwargs={'workspace_id': self.workspace.id})
        data = {'domains': ['https://example.com/api/v1']}
        
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

class AgentAndAuditLogTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(email='test_agent@example.com', password='password123', first_name='Test', last_name='User')
        self.admin = User.objects.create_user(email='admin_agent@example.com', password='password123', first_name='Admin', last_name='User')
        
        self.workspace = Workspace.objects.create(name='Test Workspace Agent', owner=self.admin, type=WorkspaceType.SHARED)
        self.membership = Membership.objects.create(
            user=self.admin, 
            workspace=self.workspace, 
            role=MembershipRole.ADMIN,
            status=MembershipStatus.ACTIVE,
            encrypted_workspace_key='key'
        )

    def test_create_agent_workspace_level(self):
        self.client.force_authenticate(user=self.admin)
        url = reverse('agent-list-create', kwargs={'workspace_id': self.workspace.id})
        data = {'name': 'test-agent', 'label': 'Initial Token'}
        
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data['data']['agent']['name'], 'test-agent')
        self.assertIn('token', response.data['data'])

    def test_list_agents(self):
        from .models import AgentRegistration
        AgentRegistration.objects.create(workspace=self.workspace, name='agent-1', created_by=self.admin)
        
        self.client.force_authenticate(user=self.admin)
        url = reverse('agent-list-create', kwargs={'workspace_id': self.workspace.id})
        
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['data']), 1)

    def test_create_token(self):
        from .models import AgentRegistration
        agent = AgentRegistration.objects.create(workspace=self.workspace, name='agent-1', created_by=self.admin)
        
        self.client.force_authenticate(user=self.admin)
        url = reverse('agent-token-list-create', kwargs={'registration_id': agent.id})
        data = {'label': 'New Token'}
        
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, 201)
        self.assertIn('token', response.data['data'])

    def test_verify_agent_internal(self):
        from .models import AgentRegistration, AgentToken
        import hashlib
        agent = AgentRegistration.objects.create(workspace=self.workspace, name='agent-1', created_by=self.admin)
        raw_token = 'test-token'
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        token = AgentToken.objects.create(
            registration=agent, 
            workspace=self.workspace, 
            token_hash=token_hash,
            created_by=self.admin
        )
        
        url = reverse('internal-agent-verify')
        data = {'token_id': token.id, 'token': raw_token}
        
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data['valid'])
        self.assertEqual(response.data['agent_id'], agent.id)

    def test_create_audit_log_internal(self):
        from django.utils import timezone
        url = reverse('internal-audit-log-create')
        data = {
            'workspace_id': str(self.workspace.id),
            'timestamp': timezone.now().isoformat(),
            'target_domain': 'example.com',
            'target_url': 'https://example.com/api',
            'target_path': '/api',
            'method': 'GET',
            'duration_ms': 100,
            'credential_ref': 'cred_123',
            'injection_style': 'header',
            'resolution_path': 'direct',
            'caller_role': 'admin'
        }
        
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data['created_count'], 1)

