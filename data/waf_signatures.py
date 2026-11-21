"""WAF fingerprint database."""

WAF_SIGNS = [
    ('Cloudflare', ['cf-ray', '__cf_chl', 'cf-chl', 'cloudflare']),
    ('Sucuri', ['x-sucuri-id', 'sucuri']),
    ('Imperva', ['x-iinfo', 'incap_ses', 'imperva']),
    ('Akamai', ['akamai', 'ak-bmsc']),
    ('AWS WAF', ['awselb', 'x-amzn-requestid']),
    ('Wordfence', ['wordfence', 'wfvt_']),
    ('ModSecurity', ['mod_security', 'modsecurity']),
    ('F5 BIG-IP', ['bigip', 'tsabc']),
    ('Barracuda', ['barra_counter_session']),
]

# statuses that count as WAF-blocked responses
BLOCK_STATUS = (403, 406, 429, 501, 503, 520, 521, 522, 523, 524)

# block-page strings that mean the WAF is challenging us, not serving content
BLOCK_MARKERS = ('captcha', 'access denied', 'just a moment', 'attention required')
