
import unittest
import json
from unittest import mock
from threading import Thread
from http.server import SimpleHTTPRequestHandler, HTTPServer
from requests.models import Response
from ..address import Address
from ..paymentrequest import get_payment_request
from ..bitcoin import sha256, deserialize_privkey, regenerate_key
from .. import paymentrequest_pb2 as pb2


class Test_PaymentRequests_BIP70(unittest.TestCase):

    def setUp(self):
        self.serv = None
        self.th = None

    def tearDown(self):
        if self.serv is not None:
            self.serv.shutdown()
        if self.th is not None:
            self.th.join()

    # Verify that an error is received when an unsupported (non http/https/file) is used
    def test_get_payment_request_unsupported_scheme(self):
        pr = get_payment_request("ftp://something.com")

        self.assertTrue(pr.error is not None)

    # Verify that an error is received when we contact a non-existing server
    def test_get_payment_request_nonexistant_server(self):
        pr = get_payment_request("http://localhost:4321")

        self.assertTrue(pr.error is not None)

    # Verify that an error is received if the server does not respond with
    # 'application/bitcoincash-paymentrequest' as content type
    def test_get_payment_request_unsupported_contenttype(self):
        class RequestHandler(SimpleHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                resp = b"This is an invalid PaymentRequest"
                self.send_header('Content-type', 'text/plain')
                self.send_header('Content-length', len(resp))
                self.end_headers()
                self.wfile.write(resp)

        self.serv = DummyServer(RequestHandler)
        self.th = Thread(target=self.serv.start_serve)

        self.th.start()
        pr = get_payment_request("http://localhost:1234")

        self.assertTrue(pr.error is not None)

    # Verify that an error is received if the data in the Payment Request is garbage
    def test_get_payment_request_invalid_payment_data(self):
        class RequestHandler(SimpleHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                resp = b'1'
                self.send_header('Content-type', 'application/bitcoincash-paymentrequest')
                self.send_header('Content-length', len(resp))
                self.end_headers()
                self.wfile.write(resp)

        self.serv = DummyServer(RequestHandler)
        self.th = Thread(target=self.serv.start_serve)
        self.th.start()
        pr = get_payment_request("http://localhost:1234")

        self.assertTrue(pr.error is not None)

    # Verify that we get an error if the server responded with error 503
    def test_get_payment_request_error_503(self):
        class RequestHandler(SimpleHTTPRequestHandler):
            def do_GET(self):
                resp = b''
                self.send_response(503)
                self.send_header('Content-type', 'application/bitcoincash-paymentrequest')
                self.send_header('Content-length', len(resp))
                self.end_headers()
                self.wfile.write(resp)

        self.serv = DummyServer(RequestHandler)
        self.th = Thread(target=self.serv.start_serve)
        self.th.start()
        pr = get_payment_request("http://localhost:1234/invoice")

        self.assertTrue(pr.error is not None)

    # Verify that a trivial payment request can be parsed and sent
    def test_send_payment_trivial(self):
        class RequestHandler(SimpleHTTPRequestHandler):
            def do_GET(self):
                resp = b''
                if self.path == "/invoice":
                    pr = pb2.PaymentRequest()
                    pd = pb2.PaymentDetails()
                    pd.memo = "dummy_memo"
                    pd.time = 0
                    pd.payment_url = "http://localhost:1234/pay"
                    pd.outputs.add(amount=0, script=b'')
                    pr.serialized_payment_details = pd.SerializeToString()
                    resp = pr.SerializeToString()

                self.send_response(200)
                self.send_header('Content-type', 'application/bitcoincash-paymentrequest')
                self.send_header('Content-length', len(resp))
                self.end_headers()
                self.wfile.write(resp)

            def do_POST(self):
                resp = b''
                if self.path == "/pay":
                    pa = pb2.PaymentACK()
                    post_data = self.rfile.read(int(self.headers['Content-Length']))
                    pa.payment.ParseFromString(post_data)
                    pa.memo = "dummy_memo_ack"
                    resp = pa.SerializeToString()

                self.send_response(200)
                self.send_header('Content-type', 'application/bitcoin-paymentack')
                self.send_header('Content-length', len(resp))
                self.end_headers()
                self.wfile.write(resp)

        self.serv = DummyServer(RequestHandler)
        self.th = Thread(target=self.serv.start_serve)
        self.th.start()
        pr = get_payment_request("http://localhost:1234/invoice")

        self.assertTrue(pr.error is None)
        self.assertTrue(pr.get_memo() == "dummy_memo")
        self.assertTrue(pr.get_payment_url() == "http://localhost:1234/pay")

        ack, memo = pr.send_payment('010203', Address.from_string("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"))
        self.assertEqual(ack, True)
        self.assertEqual(memo, "dummy_memo_ack")

class DummyServer:
    def __init__(self, handler):
        self.httpd = HTTPServer(('localhost', 1234), handler)

    def start_serve(self):
        self.httpd.serve_forever()

    def shutdown(self):
        self.httpd.shutdown()
        self.httpd.server_close()

def _signed_response() -> Response:
    payment_req_data = {
        'time': '2020-01-24T18:57:44.509Z',
        'expires': '2055-01-24T19:12:44.509Z',
        'memo': 'dummy_memo',
        'paymentUrl': 'https://bitpay.com/i/test123',
        'paymentId': 'test123',
        'chain': 'BCH',
        'network': 'main',
        'requiredFeePerByte': 1,
        'outputs': [
            {
                'amount': 39300,
                'address': '18AvdeMTZm63MEriLRYkeC9dJhHnZ9jtJt'
            }
        ]
    }
    # privkey: KzMFjMC2MPadjvX5Cd7b8AKKjjpBSoRKUTpoAtN6B3J9ezWYyXS6
    # pubkey: 02c6467b7e621144105ed3e4835b0b4ab7e35266a2ae1c4f8baa19e9ca93452997
    response = Response()
    response.status_code = 200
    response._content = str.encode(json.dumps(payment_req_data))
    response.headers['digest'] = 'SHA-256=%s' % sha256(response._content).hex()
    _, privkey, _ = deserialize_privkey('KzMFjMC2MPadjvX5Cd7b8AKKjjpBSoRKUTpoAtN6B3J9ezWYyXS6')
    key = regenerate_key(privkey)
    response.headers['signature'] = key.sign(sha256(response._content)).hex()
    response.headers['x-identity'] = '17azqT8T16coRmWKYFj3UjzJuxiYrYFRBR'
    response.url = 'https://bitpay.com/i/test123'
    return response

class Test_PaymentRequests_BitPay(unittest.TestCase):
    def mocked_bitpay_requests_get_correct_sig(*args, **kwargs):
        assert 'application/payment-request' == kwargs['headers']['accept']
        response = _signed_response()
        return response

    # Verify that a payment request verification is successfull
    @mock.patch('requests.get', side_effect=mocked_bitpay_requests_get_correct_sig)
    def test_bitpay_verify(self, mock_get):
        pr = get_payment_request('https://bitpay.com/invoice')
        self.assertTrue(pr.error is None)
        self.assertEqual(pr.get_memo(), 'dummy_memo')
        self.assertEqual(pr.get_payment_url(), 'https://bitpay.com/i/test123')
        self.assertTrue(pr.verify(None))
        self.assertEqual(pr.get_requestor(), 'BitPay, Inc.')

    def mocked_bitpay_requests_get_incorrect_digest(*args, **kwargs):
        response = _signed_response()
        # Trash digest by flipping last bit
        response.headers['digest'] = response.headers['digest'][:-1] + chr(ord(response.headers['digest'][-1])^0x1)
        return response

    # Verify that a payment request verification fails if the digest is incorrect
    @mock.patch('requests.get', side_effect=mocked_bitpay_requests_get_incorrect_digest)
    def test_bitpay_verify_incorrect_digest(self, mock_get):
        pr = get_payment_request('https://bitpay.com/invoice')
        self.assertTrue(pr.error is None)
        self.assertEqual(pr.get_memo(), 'dummy_memo')
        self.assertEqual(pr.get_payment_url(), 'https://bitpay.com/i/test123')
        self.assertFalse(pr.verify(None))

    def mocked_bitpay_requests_get_incorrect_signature(*args, **kwargs):
        response = _signed_response()
        # Trash signature by flipping last bit
        response.headers['signature'] = response.headers['signature'][:-1] + chr(ord(response.headers['signature'][-1])^0x1)
        return response

    # Verify that a payment request verification fails if the signature is incorrect
    @mock.patch('requests.get', side_effect=mocked_bitpay_requests_get_incorrect_signature)
    def test_bitpay_verify_incorrect_signature(self, mock_get):
        pr = get_payment_request('https://bitpay.com/invoice')
        self.assertTrue(pr.error is None)
        self.assertEqual(pr.get_memo(), 'dummy_memo')
        self.assertEqual(pr.get_payment_url(), 'https://bitpay.com/i/test123')
        self.assertFalse(pr.verify(None))

    def mocked_bitpay_requests_request(*args, **kwargs):
        response = _signed_response()
        return response

    # Verify that a valid jsonPaymentRequest response fails on other domains then bitpay.com
    @mock.patch('requests.request', side_effect=mocked_bitpay_requests_request)
    def test_bitpay_get_payment_request_other_domain(self, mock_get):
        pr = get_payment_request('https://buttpay.com/invoice')
        self.assertTrue(pr.error is not None)

    def mocked_bitpay_requests_request_w_content(*args, **kwargs):
        response = _signed_response()
        response.headers['Content-Type'] = 'application/bitcoincash-paymentrequest'
        return response

    # Verify that a valid jsonPaymentRequest response fails on other domains then bitpay.com
    # Set the Content-Type for BIP-70 to try and trick the client
    @mock.patch('requests.request', side_effect=mocked_bitpay_requests_request_w_content)
    def test_bitpay_get_payment_request_other_domain_content_type(self, mock_get):
        pr = get_payment_request('https://buttpay.com/invoice')
        self.assertTrue(pr.error is not None)
