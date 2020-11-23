from pastehunter.common import base62_decode, base62_encode


def test_b62_encode():
    assert base62_encode(622708) == '2BZG'
    assert base62_encode(622707) == '2BZF'


def test_b62_decode():
    assert base62_decode('1') == 1
    assert base62_decode('a') == 10
    assert base62_decode('2BZF') == 622707
    assert base62_decode('2BZG') == 622708