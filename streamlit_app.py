"""Ghostify's source-analysis browser interface."""
import hmac
import json
import os
import streamlit as st
from web.runner import run_audit

st.set_page_config(page_title='Ghostify · Repository review', page_icon='👻', layout='wide')
st.title('Ghostify')
st.caption('Repository security review • Source analysis • AI-assisted summaries')
st.write('Turn a public GitHub repository into a structured security report. Inspect findings, review the summary, and download the results.')

password = os.getenv('GHOSTIFY_ACCESS_PASSWORD', '')
if not password:
    st.info('Deployment setup is incomplete: set GHOSTIFY_ACCESS_PASSWORD in the host environment.')
    st.stop()
if not st.session_state.get('authenticated'):
    with st.form('login'):
        entered = st.text_input('Access password', type='password')
        login = st.form_submit_button('Open workspace')
    if login:
        if hmac.compare_digest(entered.encode(), password.encode()):
            st.session_state.authenticated = True
            st.rerun()
        else:
            st.error('Incorrect password.')
    st.stop()

if st.sidebar.button('Sign out'):
    st.session_state.clear()
    st.rerun()
st.sidebar.header('Source review')
st.sidebar.write('Public repositories from configured owners. Reports stay in this browser session and can be downloaded.')
st.sidebar.caption('This hosted workflow does not run dynamic API tests. Findings need human verification.')

if not os.getenv('GOOGLE_API_KEY'):
    st.warning('Add GOOGLE_API_KEY to the host environment to enable analysis.')
    st.stop()

with st.form('audit'):
    url = st.text_input('GitHub repository', placeholder='https://github.com/quixoticalcoder/your-project')
    authorized = st.checkbox('I own this repository or have permission to analyze it and send relevant source findings to Google Gemini.')
    submitted = st.form_submit_button('Analyze repository', type='primary')
if submitted:
    if not authorized:
        st.error('Confirm repository permission before starting.')
    else:
        st.session_state.pop('result', None)
        try:
            with st.spinner('Inspecting source code and preparing your report. This can take several minutes.'):
                st.session_state.result = run_audit(url)
        except (ValueError, RuntimeError) as exc:
            st.error(str(exc))

if 'result' in st.session_state:
    result = st.session_state.result
    report = result['report']
    st.subheader('Review results')
    st.caption(result['repository'])
    totals = report.get('summary', {})
    cols = st.columns(3)
    cols[0].metric('Reported findings', totals.get('total_vulnerabilities', 0))
    cols[1].metric('High severity', totals.get('by_severity', {}).get('HIGH', 0))
    cols[2].metric('Medium severity', totals.get('by_severity', {}).get('MEDIUM', 0))
    st.caption('An empty report is not proof of security. External scanners may have incomplete coverage or fail independently.')
    summary, findings = st.tabs(['Summary', 'Findings'])
    with summary:
        st.text(result.get('summary') or 'No summary was returned.')
    with findings:
        st.json(report)
    st.download_button('Download JSON report', json.dumps(result, indent=2), 'ghostify-report.json', 'application/json')
    st.download_button('Download summary', result.get('summary', ''), 'ghostify-summary.txt', 'text/plain')
