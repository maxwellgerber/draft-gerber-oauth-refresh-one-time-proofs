# Runs client.mjs in real Chromium against the Node AS, for each signature algorithm.
import json, subprocess, sys, time, os
from playwright.sync_api import sync_playwright
here = os.path.dirname(os.path.abspath(__file__))
open(os.path.join(here, 'stats.json'), 'w').write('{}')
srv = subprocess.Popen(['node', 'serve.mjs'], cwd=here, env={**os.environ, 'PORT': '8790'}, stdout=subprocess.PIPE)
srv.stdout.readline()
URL = 'http://127.0.0.1:8790/'
results = []
def check(name, cond, detail=''):
    results.append(bool(cond)); print(('PASS ' if cond else 'FAIL ') + name + (f'  [{detail}]' if detail else ''))
is_at = lambda r: isinstance(r.get('ok'), str) and len(r['ok']) >= 40
try:
    with sync_playwright() as p:
        browser = p.chromium.launch(args=['--no-proxy-server'])
        print('Chromium', browser.version)
        for alg, keyname in (('ES256', 'ECDSA'), ('Ed25519', 'Ed25519')):
            ctx = browser.new_context()
            page = ctx.new_page(); page.goto(URL); page.wait_for_function('window.ready')
            opt = json.dumps({'alg': alg})
            if alg == 'ES256':
                md = page.evaluate('api.metadata()')
                check('metadata lists supported algorithms', md.get('refresh_proof_alg_values_supported') == ['ES256', 'Ed25519'])
            check(f'{alg}: code exchange with a Chromium-generated JWK', is_at(page.evaluate(f'api.login({opt})')))
            check(f'{alg}: 3 refreshes verified by node:crypto', all(is_at(page.evaluate('api.refresh()')) for _ in range(3)))
            info = page.evaluate('api.inspect()')
            check(f'{alg}: private key extractable=false, exportKey rejects, storage dump has no key bytes',
                  info['keyAlg'] == keyname and info['extractable'] is False and info['exportWorks'] is False and '"key":{}' in info['stateJson'])
            page.reload(); page.wait_for_function('window.ready')
            check(f'{alg}: refresh after reload uses the key handle persisted in IndexedDB', is_at(page.evaluate('api.refresh()')))

            state = {'n': 0}
            def drop_response_once(route):
                state['n'] += 1
                if state['n'] == 1: route.fetch(); route.abort('connectionreset')
                else: route.continue_()
            page.route('**/token', drop_response_once)
            check(f'{alg}: lost response recovers (duplicate, then next counter)', is_at(page.evaluate('api.refresh()')), f"{state['n']} exchanges")
            page.unroute('**/token')

            if alg == 'ES256':
                state['n'] = 0
                def drop_request_once(route):
                    state['n'] += 1
                    route.abort('connectionreset') if state['n'] == 1 else route.continue_()
                page.route('**/token', drop_request_once)
                check('lost request recovers', is_at(page.evaluate('api.refresh()')), f"{state['n']} exchanges")
                page.unroute('**/token')

                page.route('**/token', lambda route: route.fetch())   # AS processes; response never delivered
                page.evaluate('void api.refresh()')
                time.sleep(0.5)
                pending = page.evaluate('api.inspect()')['pending']
                page.close()
                page = ctx.new_page(); page.goto(URL); page.wait_for_function('window.ready')
                check('pending attempt was durable before the tab died', pending is not None, json.dumps(pending))
                check('new tab resends the pending attempt and recovers', is_at(page.evaluate('api.refresh()')))

                tabs = [page] + [ctx.new_page() for _ in range(2)]
                for t in tabs[1:]: t.goto(URL); t.wait_for_function('window.ready')
                for t in tabs: t.evaluate('window.batch = Promise.all(Array.from({length: 10}, () => api.refresh()))')
                outs = [r for t in tabs for r in t.evaluate('window.batch')]
                check('30 concurrent refreshes across 3 tabs under a Web Lock all succeed', all(is_at(r) for r in outs) and len({r['ok'] for r in outs}) == 30)
            last = page
        time.sleep(0.15)
        s = last.evaluate("fetch('/stats').then(r => r.json())")
        check('AS saw zero revocations and zero bad proofs', s['revocations'] == 0 and s['badProofs'] == 0, json.dumps(s))
        browser.close()
finally:
    srv.terminate()
print(f'{sum(results)}/{len(results)} passed'); sys.exit(0 if all(results) else 1)
