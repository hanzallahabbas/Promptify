import unittest
from unittest.mock import patch

from app import app


class DatabaseFlowTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    @patch('auth.users_col', None)
    def test_register_returns_service_unavailable_when_database_is_unavailable(self):
        response = self.client.post(
            '/register',
            json={
                'name': 'Test User',
                'email': 'test@example.com',
                'password': 'password123',
            },
        )

        self.assertEqual(response.status_code, 503)
        self.assertIn('database', response.get_json()['error'].lower())


if __name__ == '__main__':
    unittest.main()
