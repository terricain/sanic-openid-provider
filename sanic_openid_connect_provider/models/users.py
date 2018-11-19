import datetime
import logging
from typing import Dict, Any, List, Union, KeysView

import sanic.request

TEST_USER = {
    'username': 'testuser',  # Required
    'consent': False,  # Required
    'auth_time': datetime.datetime.now().timestamp(),
    'name': 'John Wick',
    'given_name': 'john',
    'family_name': 'wick',
    'gender': 'male',
    'locale': 'en-us',
    'email': 'johnwick@gmail.com',
    'email_verified': True,
    'address': {
        'formatted': '500 On Fire Hose, USA',
        'street_address': '500 On Fire Hose',
        'locality': 'New York',
        'region': 'No clue',
        'postal_code': 'NY12354',
        'country': 'United States of America'
    },
    'phone_number': '07428555555',
    'phone_number_verified': True

}

SCOPES = {
    'profile': ['name', 'family_name', 'given_name', 'middle_name', 'nickname', 'preferred_username', 'profile', 'picture', 'website', 'gender', 'birthdate', 'zoneinfo', 'locale', 'updated_at'],
    'email': ['email', 'email_verified'],
    'address': ['address'],
    'phone': ['phone_number', 'phone_number_verified']
}

logger = logging.getLogger('oicp')


class UserManager(object):
    def __init__(self, provider=None):
        self._provider = provider

    def set_provider(self, provider):
        self._provider = provider

    async def setup(self):
        pass

    async def is_authenticated(self, request: sanic.request.Request) -> bool:
        user_sess = request['session'].get('user')
        if user_sess:
            max_age = int(request.args.get('max_age', '0') if request.method == 'GET' else request.form.get('max_age', '0'))

            # If they havent provided max_time, then your authed
            if max_age > 0:
                now = datetime.datetime.now().timestamp()

                # If the time since you authed is greater than max_time, clear session
                if (now - user_sess['auth_time']) > max_age:
                    request['session'].clear()
                    return False
                else:
                    return True

            else:
                return True
        return False

    async def get_user(self, request: sanic.request.Request) -> Dict[str, Any]:
        session_user = request['session']['user']

        return self.user_data_to_claims(session_user)

    async def get_user_by_username(self, username: str) -> Dict[str, Any]:
        # Get this by other means
        return self.user_data_to_claims(TEST_USER)

    @classmethod
    def clean_list(cls, dirty_list) -> List[Any]:
        result = []

        for item in dirty_list:
            if isinstance(item, dict):
                item = cls.clean_dict(item)
            elif isinstance(item, (list, tuple, set)):
                item = cls.clean_list(item)

            if item:
                result.append(item)

        return result

    @classmethod
    def clean_dict(cls, dirty_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Strips out empty values
        """

        result = {}

        for key, value in dirty_dict.items():
            if not value:
                continue
            elif isinstance(value, dict):
                result[key] = cls.clean_dict(value)
            elif isinstance(value, (list, tuple, set)):
                result[key] = cls.clean_list(value)
            else:
                result[key] = value

        return result

    @staticmethod
    def user_data_to_claims(user_data: Any) -> Dict[str, Any]:
        """
        Converts random format user_data is in, to a standardised format

        Add any specific pieces of data here
        """

        first_name = user_data['name'].split(' ', 1)[0]
        last_name = user_data['name'].split(' ', 1)[-1]

        return {
            'username': user_data['username'],
            'consent': user_data['consent'],
            'auth_time': user_data['auth_time'],
            'name': user_data['name'],
            'given_name': first_name,
            'family_name': last_name,
            'gender': user_data['gender'],
            'locale': user_data['locale'],
            'email': user_data['email'],
            'email_verified': user_data['email_verified'],
            'address': {
                'formatted': user_data['address']['formatted'],
                'street_address': user_data['address']['street_address'],
                'locality': user_data['address']['locality'],
                'region': user_data['address']['region'],
                'postal_code': user_data['address']['postal_code'],
                'country': user_data['address']['country']
            },
            'phone_number': user_data['phone_number'],
            'phone_number_verified': user_data['phone_number_verified'],

            'nickname': user_data.get('nickname'),
            'profile': user_data.get('profile'),
            'picture': user_data.get('picture'),
            'website': user_data.get('website'),
            'birthdate': user_data.get('birthdate'),
            'zoneinfo': user_data.get('zoneinfo'),
            'updated_at': user_data.get('updated_at')
        }

    @staticmethod
    def add_scopes(scopes: Dict[str, Any]):
        for scope, claims in scopes.items():
            if not isinstance(claims, (list, tuple, set)):
                logging.error('Claims {0} is not a list'.format(type(claims)))
                continue

            SCOPES[scope] = claims
            logging.info('Added scope {0}: {1}'.format(scope, claims))

    async def get_claims_for_user_by_scope(self, username: str, scopes: List[str], specific_claims: Union[List[str], KeysView]) -> Dict[str, Any]:
        user_data = await self.get_user_by_username(username)

        return self.get_claims_for_userdata_by_scope(user_data, scopes, specific_claims)

    def get_claims_for_userdata_by_scope(self, user_data: Dict[str, Any], scopes: List[str], specific_claims: List[str]) -> Dict[str, Any]:
        result = {}

        # Get all claims for the scope
        for scope in scopes:
            if scope not in SCOPES:
                logger.warning('Requested unknown scope {0}'.format(scope))
                continue

            for claim in SCOPES[scope]:
                try:
                    result[claim] = user_data[claim]
                except KeyError:
                    pass

        # Get some specific claims if they ask for them
        for claim in specific_claims:
            try:
                result[claim] = user_data[claim]
            except KeyError:
                pass

        return self.clean_dict(result)
