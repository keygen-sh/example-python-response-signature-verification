from ed25519 import BadSignatureError
from urllib.parse import quote
from hashlib import sha256
import requests
import ed25519
import base64
import json
import sys
import os
import re

# Run from the command line:
#   python main.py /licenses/foo
path = sys.argv[1]

uri = '/v1/accounts/{}/{}'.format(os.environ['KEYGEN_ACCOUNT_ID'], path.strip('/'))
url = 'https://api.keygen.sh' + uri

res = requests.get(url,
  headers={
    'Authorization': 'Bearer {}'.format(os.environ['KEYGEN_PRODUCT_TOKEN']),
    'Accept': 'application/vnd.api+json',
  },
)

try:
  signature = res.headers.get('Keygen-Signature')
  assert signature != None, 'signature is missing'

  # Parse signature header
  values = [v.split('=', 1) for v in re.split(r"\s*,\s*", signature)]
  values = [(k, v.strip('"')) for (k, v) in values]
  params = dict(values)
  assert params['algorithm'] == 'ed25519', 'algorithm is unsupported'

  # Verify digest header
  value = base64.b64encode(sha256(res.text.encode()).digest())
  digest = 'sha-256={}'.format(value.decode())
  assert digest == res.headers.get('Digest'), 'digest did not match'

  # Build signing data
  date = res.headers.get('Date')
  signing_data = ''.join([
    '(request-target): {method} {uri}\n'.format(method='get', uri=quote(uri, safe='/?=&')),
    'host: api.keygen.sh\n',
    'date: {}\n'.format(date),
    'digest: {}'.format(digest),
  ])

  # Verify response signature
  verify_key = ed25519.VerifyingKey(
    os.environ['KEYGEN_PUBLIC_KEY'].encode(),
    encoding='hex',
  )

  verify_key.verify(
    base64.b64decode(params['signature']),
    signing_data.encode(),
  )

  # Print verified response
  print(
    json.dumps(res.json(), indent=2),
  )
except Exception as e:
  print(
    'signature verification failed: {}'.format(e),
  )

  if 'DEBUG' in os.environ:
    print(res.text)
