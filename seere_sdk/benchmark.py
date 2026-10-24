"""Synthetic, reproducible accuracy and ranking evaluation; no live credentials."""
from .detection import inspect_text
from .rag import suspicion

CASES = [
 ('openai', ''.join(('sk-', 'proj-', 'SYNTHETICONLY1234567890abcdefghij')), True),
 ('anthropic', ''.join(('sk-', 'ant-', 'SYNTHETICONLY1234567890abcdefghij')), True),
 ('aws', ''.join(('AKIA', 'ABCDEFGHIJKLMNOP')), True),
 ('github', ''.join(('ghp_', 'SYNTHETICONLY1234567890abcdefghijklm')), True),
 ('stripe', ''.join(('sk_test_', 'SYNTHETICONLY1234567890abcdef')), True),
 ('google', ''.join(('AIza', 'SYNTHETICONLY1234567890abcdefghijklm')), True),
 ('json', '{"password":"SyntheticPassword987!x"}', True),
 ('aws-file', 'aws_secret_access_key = SyntheticOnly7890ABCxyz', True),
 ('pem', '-----BEGIN PRIVATE KEY-----\nSyntheticOnlyBase64ab123456\n-----END PRIVATE KEY-----', True),
 ('env-reference', 'API_KEY=${MANAGED_SECRET}', False),
 ('placeholder', 'api_key = your_api_key', False),
 ('prose', 'The service uses managed identity.', False),
 ('hash', 'file_digest = aabbccddeeff00112233445566778899', False),
 ('public-key', '-----BEGIN PUBLIC KEY-----\nSyntheticOnly123\n-----END PUBLIC KEY-----', False),
 ('short', 'password = abc', False),
 ('ordinary-json', '{"title":"Release documentation"}', False),
]


def benchmark(key):
    tp = fp = tn = fn = 0
    cases = []
    for name, text, expected in CASES:
        actual = bool(inspect_text(text, 'benchmark', name, key))
        tp += actual and expected
        fp += actual and not expected
        tn += not actual and not expected
        fn += not actual and expected
        cases.append({'case': name, 'expected_positive': expected, 'detected': actual})
    # Separate relevance corpus: cosine ranks passages for review, not credential assertions.
    passages = [
        ('credential-guide', 'production api key password secret credential authentication', True),
        ('rotation-note', 'service account private key access token production', True),
        ('opaque-reference', 'authentication credential secret is stored in vault entry ZXQ', True),
        ('weather', 'sunshine and rain across the mountains', False),
        ('release', 'release notes for version two', False),
        ('design', 'button color typography margins', False),
    ]
    ranked = sorted([{'id': name, 'score': round(suspicion(text),6), 'relevant': relevant,
        'regex_detected': bool(inspect_text(text, 'benchmark', name, key))}
        for name,text,relevant in passages], key=lambda row: -row['score'])
    top = ranked[:3]
    additional = sum(r['relevant'] and not r['regex_detected'] for r in top)
    return {'dataset': 'synthetic-v1', 'cases': cases, 'true_positive':tp, 'false_positive':fp,
        'true_negative':tn, 'false_negative':fn, 'precision':tp/(tp+fp) if tp+fp else 0,
        'recall':tp/(tp+fn) if tp+fn else 0, 'false_positive_rate':fp/(fp+tn) if fp+tn else 0,
        'ranking': {'method':'lexical cosine', 'top_k':3, 'precision_at_k':sum(r['relevant'] for r in top)/3,
            'additional_relevant_review_passages':additional, 'ranked':ranked},
        'limitation':'Small synthetic fixtures; relevance is not additional confirmed credential detection. Not customer accuracy.'}
