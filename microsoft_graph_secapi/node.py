import logging
import os
import shutil
import time
import uuid
import netaddr
from datetime import datetime, timedelta
from collections import deque

import adal  #pylint: disable=E0401
import gevent
import requests
import yaml
import ujson as json
from gevent.queue import Queue, Empty, Full
from netaddr import IPNetwork
from requests.exceptions import RequestException, HTTPError

from minemeld.ft import ft_states  #pylint: disable=E0401
from minemeld.ft.base import _counting  #pylint: disable=E0401
from minemeld.ft.actorbase import ActorBaseFT  #pylint: disable=E0401

LOG = logging.getLogger(__name__)
AUTHORITY_BASE_URL = 'https://login.microsoftonline.com'
AUTHORITY_URL = 'https://login.microsoftonline.com/{}'
RESOURCE = 'https://graph.microsoft.com/'
ENDPOINT_VERSION='beta'
ENDPOINT_URL = 'https://graph.microsoft.com/{}/security/tiIndicators'.format(ENDPOINT_VERSION)
ENDPOINT_SUBMITBATCH=ENDPOINT_URL+'/submitTiIndicators'
ENDPOINT_DELETEBATCH=ENDPOINT_URL+'/deleteTiIndicatorsByExternalId'

# Maximum number of batch upload
MAX_BATCH_SIZE=50

HASH_2_ISG = {
    'sha1': 1,
    'sha256': 2,
    'md5': 3
}

SHARE_LEVEL_2_ISG = {
    'white': 1,
    'green': 2,
    'amber': 3,
    'red': 4
}

EXPIRED = datetime.fromtimestamp(0).isoformat()


class AuthConfigException(RuntimeError):
    pass

class SecurityGraphResponseException(RuntimeError):
    pass

class Output(ActorBaseFT):
    def __init__(self, name, chassis, config):
        self._queue = None

        super(Output, self).__init__(name, chassis, config)

        self._push_glet = None
        self._checkpoint_glet = None

    def configure(self):
        super(Output, self).configure()

        self.queue_maxsize = int(self.config.get('queue_maxsize', 100000))
        if self.queue_maxsize == 0:
            self.queue_maxsize = None
        self._queue = Queue(maxsize=self.queue_maxsize)

        self.client_id = self.config.get('client_id', None)
        self.client_secret = self.config.get('client_secret', None)
        self.tenant_id = self.config.get('tenant_id', None)

        self.recommended_action = self.config.get('recommended_action', 3)
        self.target_product = self.config.get('target_product', None)

        self.target_product = self.config.get('target_product', 'minemeld')
        self.threat_type = self.config.get('threat_type', 'malware')

        self.side_config_path = self.config.get('side_config', None)
        if self.side_config_path is None:
            self.side_config_path = os.path.join(
                os.environ['MM_CONFIG_DIR'],
                '%s_side_config.yml' % self.name
            )

        self._load_side_config()

    def _load_side_config(self):
        try:
            with open(self.side_config_path, 'r') as f:
                sconfig = yaml.safe_load(f)

        except Exception as e:
            LOG.error('%s - Error loading side config: %s', self.name, str(e))
            return

        client_id = sconfig.get('client_id', None)
        if client_id is not None:
            self.client_id = client_id
            LOG.info('{} - client_id set'.format(self.name))

        client_secret = sconfig.get('client_secret', None)
        if client_secret is not None:
            self.client_secret = client_secret
            LOG.info('{} - client_secret set'.format(self.name))

        tenant_id = sconfig.get('tenant_id', None)
        if tenant_id is not None:
            self.tenant_id = tenant_id
            LOG.info('{} - tenant_id set'.format(self.name))

        recommended_action = sconfig.get('recommended_action', None)
        if recommended_action is not None:
            self.recommended_action = recommended_action
            LOG.info('{} - recommended_action set'.format(self.name))

        target_product = sconfig.get('target_product', None)
        if target_product is not None:
            self.target_product = target_product
            LOG.info('{} - target_product set'.format(self.name))

    def connect(self, inputs, output):
        output = False
        super(Output, self).connect(inputs, output)


    def initialize(self):
        pass

    def rebuild(self):
        pass

    def reset(self):
        pass

    def _get_auth_token(self):
        if self.client_id is None:
            LOG.error('{} - client_id not set'.format(self.name))
            raise AuthConfigException('{} - client_id not set'.format(self.name))
        if self.client_secret is None:
            LOG.error('{} - client_secret not set'.format(self.name))
            raise AuthConfigException('{} - client_secret not set'.format(self.name))
        if self.tenant_id is None:
            LOG.error('{} - tenant_id not set'.format(self.name))
            raise AuthConfigException('{} - tenant_id not set'.format(self.name))

        context = adal.AuthenticationContext(
            AUTHORITY_URL.format(self.tenant_id),
            validate_authority=self.tenant_id != 'adfs',
            api_version=None
        )

        token = context.acquire_token_with_client_credentials(
            RESOURCE,
            self.client_id,
            self.client_secret
        )

        if token is None or 'accessToken' not in token:
            LOG.error('{} - Invalid token or accessToken not available'.format(self.name))
            raise RuntimeError('{} - Invalid token or accessToken not available'.format(self.name))

        return token['accessToken']

    def _push_indicators(self, token, indicators):

        message = {
            'value': list(indicators)
        }

        LOG.debug('{} - _push_indicators message is: {}'.format(self.name, message))

        result = requests.post(
            ENDPOINT_SUBMITBATCH,
            headers={
                'Content-Type': 'application/json',
                'Authorization': 'Bearer {}'.format(token)
            },
            json=message
        )

        LOG.debug('{} - _push_indicators result is: {}'.format(self.name, result.text))

        result.raise_for_status()

        result = result.json()
        if not result or  '@odata.context' not in result or result['@odata.context'] != 'https://graph.microsoft.com/{}/$metadata#Collection(tiIndicator)'.format(ENDPOINT_VERSION):
            raise SecurityGraphResponseException('Unexpected response from Security Graph API')

        if 'value' not in result or isinstance(result['value'], list) == False or len(result['value']) < 1:
            raise SecurityGraphResponseException('Missing value from Security Graph API result')

        for v in result['value']:
            if '@odata.type' not in v or v['@odata.type'] != '#microsoft.graph.tiIndicator' or 'id' not in v or 'externalId' not in v:
                raise SecurityGraphResponseException('Missing indicator values from Security Graph response')
            
            LOG.debug('{} - Got successful id for indicator {}: {}'.format(self.name, v['externalId'], v['id']))
            if v['id'] != 'Failed to create, check Error element for reason':
                # Success!
                self.statistics['indicator.tx'] += 1


            else:
                failReason = v['Error'] if 'Error' in v else 'Unknown'
                LOG.error('{}: error creating/updating indicator {}: {}'.format(self.name, v['externalId'], failReason))
                self.statistics['error.submit'] += 1


    def _delete_indicators(self, token, indicators):


        message = {
            'value': list(set(str(i['externalId']) for i in indicators))
        }

        LOG.debug('{} - _delete_indicators message is: {}'.format(self.name, message))

        result = requests.post(
            ENDPOINT_DELETEBATCH,
            headers={
                'Content-Type': 'application/json',
                'Authorization': 'Bearer {}'.format(token)
            },
            json=message
        )

        LOG.debug('{} - _delete_indicators result is: {}'.format(self.name, result.text))

        result.raise_for_status()

        result = result.json()
        if not result or  '@odata.context' not in result or result['@odata.context'] != 'https://graph.microsoft.com/{}/$metadata#Collection(microsoft.graph.ResultInfo)'.format(ENDPOINT_VERSION):
            raise SecurityGraphResponseException('Unexpected response from Security Graph API')

        if 'value' not in result or isinstance(result['value'], list) == False or len(result['value']) < 1:
            raise SecurityGraphResponseException('Missing or incorrect value from Security Graph API result')

        for v in result['value']:
            if 'code' not in v or 'message' not in v:
                raise SecurityGraphResponseException('Missing code/message from Security Graph delete response')
            if v['code'] == "204":
                LOG.debug('_delete indicators returned success (204) for indicator {}: {}'.format(v['message'].split(' ')[0], v['message']))
                self.statistics['indicator.delete'] += 1
            else:
                LOG.error('_delete indicators returned error ({}) for indicator {}: {}'.format(v['code'], v['message'].split(' ')[0], v['message']))
                self.statistics['error.submit'] += 1                

    def _push_loop(self):
        while True:
            msg = self._queue.get()

            LOG.debug('{} - push_loop dequeued first indicator {!r}'.format(self.name, msg))

            artifacts = []
            artifacts.append(msg)

            try:
                while len(artifacts) < MAX_BATCH_SIZE:
                    m = self._queue.get_nowait()
                    artifacts.append(m)
                    LOG.debug('{} - push_loop dequeued additional indicator {!r}'.format(self.name, m))                    
            except Empty:
                pass

            # Determine which indicators must be added and which ones must be deleted
            indicatorsToDelete=deque()
            indicatorsToCreateUpdate=deque()

            for i in artifacts:
                if 'expirationDateTime' in i and i['expirationDateTime'] == EXPIRED:
                    indicatorsToDelete.append(i)
                else:
                    indicatorsToCreateUpdate.append(i)

            LOG.info('{} - _push_loop has a total of {} indicators to create/update and {} to delete'.format(self.name, len(indicatorsToCreateUpdate), len(indicatorsToDelete)))


            # Retry loop for pushing/deleting indicators
            while True:
                retries = 0

                try:

                    # Get authentication token first
                    token = self._get_auth_token()
                    LOG.debug('{} - token: {}'.format(self.name, token))

                    # Delete expired indicators before creating new ones
                    if len(indicatorsToDelete) > 0:
                        LOG.debug('{} - Deleting {} indicators'.format(self.name, len(indicatorsToDelete)))

                        try:
                            self._delete_indicators(
                                token=token,
                                indicators=indicatorsToDelete
                            )
                            # Indicators successfully deleted, empty the list
                            indicatorsToDelete=[]

                        # HTTP Error to track 4xx during the delete phase, with no retry
                        except HTTPError as e:
                            LOG.debug('{} - error deleting indicators - {}'.format(self.name, str(e)))
                            status_code = e.response.status_code

                            # If it's a 4xx, don't retry, else throw it up and go in the retry loop
                            if status_code >= 400 and status_code < 500:
                                LOG.error('{}: {} error in delete request - {}'.format(self.name, status_code, e.response.text))
                                self.statistics['error.invalid_request'] += 1
                                # this way it will continue to the create/update phase without retrying the delete in the next loop
                                indicatorsToDelete=[]
                            else:
                                raise HTTPError(e)

                        # SecurityGraph response error shouldn't trigger a retry
                        except SecurityGraphResponseException as e:
                            LOG.exception('{} - Graph Security API error deleting indicators - {}'.format(self.name, str(e)))
                            self.statistics['error.submit'] += 1
                            break

                    if len(indicatorsToCreateUpdate) > 0:
                        LOG.debug('{} - Creating/Updating {} indicators'.format(self.name, len(indicatorsToCreateUpdate)))

                        try:
                            self._push_indicators(
                                token=token,
                                indicators=indicatorsToCreateUpdate
                            )

                        # HTTP Error to track 4xx during the delete phase, with no retry
                        except HTTPError as e:
                            LOG.debug('{} - error creating/updating indicators - {}'.format(self.name, str(e)))
                            status_code = e.response.status_code

                            # If it's a 4xx, don't retry, else throw it up and go in the retry loop
                            if status_code >= 400 and status_code < 500:
                                LOG.error('{}: {} error in create/update request - {}'.format(self.name, status_code, e.response.text))
                                self.statistics['error.invalid_request'] += 1
                                # this way it will continue to the delete phase without retrying the create in the next loop
                                indicatorsToCreateUpdate=[]
                            else:
                                raise HTTPError(e)

                        # SecurityGraph response error shouldn't trigger a retry
                        except SecurityGraphResponseException as e:
                            LOG.exception('{} - Graph Securty API error creating/updating indicators - {}'.format(self.name, str(e)))
                            self.statistics['error.submit'] += 1
                            break

                    # Successful loop
                    break

                # Graceful Exit
                except gevent.GreenletExit:
                    return

                # Authentication error during token generation
                except AuthConfigException as e:
                    LOG.exception('{} - Error submitting indicators - {}'.format(self.name, str(e)))
                    self.statistics['error.submit'] += 1
                    gevent.sleep(60.0)

                # Other error, implement a retry logic
                # Note that if this hits during the delete phase, the createUpdate is never triggered
                except Exception as e:
                    LOG.exception('{} - error submitting indicators - {}'.format(self.name, str(e)))
                    self.statistics['error.submit'] += 1
                    retries += 1
                    if retries > 5:
                        break
                    gevent.sleep(120.0)

            gevent.sleep(0.1)

    def _encode_indicator(self, indicator, value, expired=False):
        type_ = value['type']

        if type_ not in [ 'URL', 'domain', 'md5', 'sha256', 'sha1', 'IPv4' ]:
            self.statistics['error.unhandled_type'] += 1
            raise RuntimeError('{} - Unhandled {}'.format(self.name, type_))


        description = '{} indicator from {}'.format(
            type_,
            ', '.join(value['sources'])
        )
        external_id = '{}:{}'.format(type_, indicator)
        expiration = datetime.utcnow() + timedelta(days=29)
        if expired:
            expiration = datetime.fromtimestamp(0)
        expiration = expiration.isoformat()

        indicators = []
        if type_ == 'IPv4' and '-' in indicator:
            a1, a2 = indicator.split('-', 1)
            r = netaddr.IPRange(a1, a2).cidrs()
            indicators = [str(i) for i in r ]
        else:
            indicators = [indicator]

        result = []
        for i in indicators:
            r = {
                'description': description,
                'confidence': value['confidence'],
                'externalId': external_id,
                'indicator': indicator,
                'expirationDateTime': expiration,
                'tlpLevel': SHARE_LEVEL_2_ISG.get(value.get('share_level', 'unknown'), 0),
                'threatType': self.threat_type
            }

            if self.recommended_action is not None:
                r['action'] = self.recommended_action

            if self.target_product is not None:
                r['targetProduct'] = self.target_product

            if type_ == 'URL':
                r['url'] = i
            elif type_ == 'domain':
                r['domainName'] = i
            elif type_ in ['md5', 'sha256', 'sha1']:
                r['fileHashType'] = HASH_2_ISG[type_]
                r['fileHashValue'] = i
            elif type_ == 'IPv4':
                parsed = netaddr.IPNetwork(i)
                if parsed.size == 1 and '/' not in i:
                    r['networkIPv4'] = i
                else:
                    r['networkCidrBlock'] = i
            else:
                # Unsupported indicator type, should never reach this code
                continue

            LOG.debug('{!r} - add indicator {!r} to queue'.format(self.name, r))

            result.append(r)

        return result

    def _checkpoint_check(self, source=None, value=None):
        t0 = time.time()

        while ((time.time() - t0) < 30) and self._queue.qsize() != 0:
            gevent.sleep(0.5)
        self._push_glet.kill()

        LOG.debug('{} - checkpoint with {} elements in the queue'.format(self.name, self._queue.qsize()))
        super(Output, self).checkpoint(source=source, value=value)

    @_counting('update.processed')
    def filtered_update(self, source=None, indicator=None, value=None):
        try:
            for i in self._encode_indicator(indicator, value, expired=False):
                self._queue.put(
                    i,
                    block=True,
                    timeout=0.001
                )
        except Full:
            self.statistics['error.queue_full'] += 1

    @_counting('withdraw.processed')
    def filtered_withdraw(self, source=None, indicator=None, value=None):
        if value is None:
            self.statistics['error.no_value'] += 1
            return

        try:
            for i in self._encode_indicator(indicator, value, expired=True):
                self._queue.put(
                    i,
                    block=True,
                    timeout=0.001
                )
        except Full:
            self.statistics['error.queue_full'] += 1

    @_counting('checkpoint.rx')
    def checkpoint(self, source=None, value=None):
        self.state = ft_states.CHECKPOINT
        self._checkpoint_glet = gevent.spawn(
            self._checkpoint_check,
            source,
            value
        )

    def length(self, source=None):
        return self._queue.qsize()

    def start(self):
        super(Output, self).start()

        self._push_glet = gevent.spawn(self._push_loop)

    def stop(self):
        super(Output, self).stop()

        if self._push_glet is not None:
            self._push_glet.kill()

        if self._checkpoint_glet is not None:
            self._checkpoint_glet.kill()

    def hup(self, source=None):
        LOG.info('%s - hup received, reload side config', self.name)
        self._load_side_config()

    @staticmethod
    def gc(name, config=None):
        ActorBaseFT.gc(name, config=config)
        shutil.rmtree(name, ignore_errors=True)