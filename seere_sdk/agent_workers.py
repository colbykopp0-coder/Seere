"""One specialist per process/container, plus a separate coordinating process."""
import argparse
import json
import os
from pathlib import Path
from .agents import LocalModel
from .reviews import review_report
from .security import safe_read
from .orchestration import correlate, load_reports


def read_json(path, limit=16_000_000):
    path = Path(path).absolute()
    return json.loads(safe_read(path.parent, path.name, limit))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('role', choices=['code','local','rag','runtime','coordinator'])
    parser.add_argument('--input', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--reviews')
    parser.add_argument('--model-endpoint', default=os.environ.get('SEERE_MODEL_ENDPOINT'))
    parser.add_argument('--model', default=os.environ.get('SEERE_MODEL'))
    parser.add_argument('--allow-container-model', action='store_true')
    parser.add_argument('--deterministic', action='store_true', help='Explicit offline fallback; no model inference')
    args = parser.parse_args()
    manifest = read_json(args.manifest, 65536)
    if args.deterministic:
        model = None
    elif not args.model_endpoint or not args.model:
        parser.error('A model endpoint and model are required unless --deterministic is explicit')
    else:
        model = LocalModel(args.model_endpoint, args.model,
            allowed_hosts=('local-model',) if args.allow_container_model else ())
    if args.role != 'coordinator':
        if args.role not in manifest['expected_modules']:
            raise ValueError('specialist_not_in_manifest')
        result = review_report(read_json(args.input), args.role, manifest['run_id'], model)
        complete = True
    else:
        if not args.reviews:
            parser.error('Coordinator requires a specialist review directory')
        reviews = []
        for module in manifest['expected_modules']:
            path = Path(args.reviews) / module / 'review.json'
            if path.exists():
                reviews.append(read_json(path))
        result = correlate(load_reports(args.input, manifest), manifest['expected_modules'],
            manifest['run_id'], model, specialist_reviews=reviews)
        complete = result['complete']
    output = Path(args.output)
    # Write atomically so a failed process cannot leave a partial result.
    temporary = output.with_name(output.name + '.tmp')
    temporary.write_text(json.dumps(result, indent=2), encoding='utf-8')
    os.replace(temporary, output)
    if not complete:
        raise SystemExit(2)


if __name__ == '__main__':
    main()
